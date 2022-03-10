use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry, result::Result};
use ansi_term::Colour;
use serde::{Serialize, Deserialize};
use std::{fs,time::SystemTime};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use itertools::Itertools;
use futures::future::join_all;

// TODO: offline ldap queries with database clone, since all custom queries are sent to LDAP service cleartext, better to send wildcard query and parse offline
// TODO: make dynamic query strings programatic, check for integer inbetween '[-' and 'DAYS]' or RFC2822 time
// TODO: rootdse, dn argument, appropriate attributes for certs

// query struct
// ldap query char escapes: https://tools.ietf.org/search/rfc2254#page-5
#[derive(Serialize, Deserialize, Debug)]
struct Query{
    name: String,
    base_dn: String,
    query: String,
    attr: Vec<String>,
}

// ldap recon tool
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// server IP
    #[clap(short, long)]
    host: String,

    /// ldap UPN username
    #[clap(short, long)]
    user: String,

    /// ldap password
    #[clap(short, long)]
    pass: String,

    /// config file (Helper Strings: [TARGETDN] [-30DAYS]) (Queries cannot contain spaces) (use * for all attributes)
    #[clap(short, long, default_value = "vulnerable.json")]
    config: String,
}

fn adtime_to_string(adtime: u128) -> Result<String>{
    if adtime == 0 {
        return Ok(String::from("0000-00-00 00:00:00"));
    }

    // 100 interval nanoseconds to seconds
    let seconds = (adtime  / 1000000000) * 100;
    // Windows NT time format 
    let ad_epoch : SystemTime = DateTime::parse_from_rfc2822("1 Jan 1601 00:00:00 +0000").unwrap().into();
    // add seconds to windows epoch
    let duration = ad_epoch + Duration::seconds(i64::try_from(seconds).unwrap()).to_std().unwrap();

    // convert duration to timestamp
    let datetime = DateTime::<Utc>::from(duration);
    let timestamp_str = datetime.format("%Y-%m-%d %H:%M:%S").to_string();

    return Ok(timestamp_str);
    // let duration = Duration::seconds(i64::try_from(seconds).unwrap());
}

// to_string helper, since you cannot impl display trait outside crate
fn resultentries_to_string(rs: Vec<ldap3::ResultEntry>) -> Result<String>{
    let mut output: String = String::from("");
    for entry in rs {
        // convert BER data to attributes
        let search_entry = SearchEntry::construct(entry);

        // add dn to string
        output.push_str(&Colour::Cyan.bold().paint(&search_entry.dn).to_string());
        // output.push_str(&search_entry.dn);
        output.push_str("\n");

        // add attributes and values to string (sorted)
        for name in search_entry.attrs.keys().sorted(){
            // add attribute name
            match name.as_str(){
                "pwdLastSet" | "LastPwdSet" | "accountExpires" | "LastLogon" | "LastLogonTimestamp" =>{
                    for value in &search_entry.attrs[name]{
                        output.push_str(&format!("{}: ",name));
                        output.push_str(&adtime_to_string(value.parse::<u128>().unwrap())?);
                        output.push_str("\n");
                    }
                },
                _ =>{
                    for value in &search_entry.attrs[name]{
                        output.push_str(&format!("{}: ",name));
                        output.push_str(&value);
                        output.push_str("\n");
                    }
                } 
            }
        }
        output.push_str("\n");
    }
    return Ok(output);
}

async fn run_query(mut ldap: Ldap, query: Query) -> Result<String>{
    let mut output = format!("{}:", Colour::Purple.underline().bold().paint(&query.name));
    output.push_str("\n");
    output.push_str(&format!("{}", Colour::Purple.paint(format!("Base: {}",&query.base_dn))));
    output.push_str("\n");
    output.push_str(&format!("{}", Colour::Purple.paint(format!("Query: {}",&query.query))));
    output.push_str("\n");

    // run query
    let (rs, _res) = ldap.search(
        &query.base_dn,
        Scope::Subtree,
        &query.query,
        &query.attr
    ).await?.success()?;

    output.push_str(&resultentries_to_string(rs).unwrap());

    return Ok(output);
}

async fn get_dn(ldap: &mut Ldap) -> Result<String>{
    let (mut rs, _res) = ldap.search("", Scope::Base, "rootDomainNamingContext=*", vec!["rootDomainNamingContext"]).await?.success()?;
    let search_entry = SearchEntry::construct(rs.pop().unwrap()); // construct needs owner not reference
    let attribute = &search_entry.attrs["rootDomainNamingContext"];
    let value = &attribute[0];

    return Ok(value.to_string());
}

#[tokio::main]
async fn main() -> Result<()> {
    // parse commandline arguments
    let args = Args::parse();

    // read queries from json file
    let config = fs::File::open(args.config).expect("config file should be provided");
    let mut queries: Vec<Query> = serde_json::from_reader(config).expect("config should be proper JSON");

    // bind to ldap server
    let (conn, mut ldap) = LdapConnAsync::new(&format!("ldap://{}:389",args.host)).await?;
    ldap3::drive!(conn);
    let _ = ldap.simple_bind(&args.user, &args.pass).await?;

    // get base dn
    let dn = get_dn(&mut ldap).await?;

    // ldap measures time as 100 nansecond intervals since January 1, 1601 UTC 
    let ad_epoch : SystemTime = DateTime::parse_from_rfc2822("1 Jan 1601 00:00:00 +0000").unwrap().into();
    let ad_ct = SystemTime::now().duration_since(ad_epoch).unwrap().as_nanos() / 100;
    let ad_year = u128::try_from(Duration::days(365).num_nanoseconds().unwrap()).unwrap() / 100;
    let ad_month = u128::try_from(Duration::days(30).num_nanoseconds().unwrap()).unwrap() / 100;
    let ad_week = u128::try_from(Duration::days(7).num_nanoseconds().unwrap()).unwrap() / 100;

    // add base_dn and dynamic query strings
    for mut query in &mut queries{
        // if base_dn contains a distinguished name but not a comma
        if query.base_dn != "" && query.base_dn.chars().last().unwrap() != ',' {
            query.base_dn.push_str(",");
        }
        // add dn to query base_dn search
        query.base_dn.push_str(&dn);
        // replaces strings in dynamic queries
        query.query = str::replace(&query.query, "[TARGETDN]",&dn);
        query.query = str::replace(&query.query, "[-1YEAR]",&(ad_ct - ad_year).to_string());
        query.query = str::replace(&query.query, "[-30DAYS]",&(ad_ct - ad_month).to_string());
        query.query = str::replace(&query.query, "[-7DAYS]",&(ad_ct - ad_week).to_string());
    }
    
    // asynchronously run queries
    let mut futures:Vec<_> = Vec::new();
    for query in queries{
        let ldap_clone = ldap.clone();
        futures.push(run_query(ldap_clone, query));
    }

    // await futures and print results
    let output = join_all(futures).await;
    for result in output{
        println!("{}", result?);
    }

    Ok(ldap.unbind().await?)
}