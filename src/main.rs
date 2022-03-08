use ldap3::{Ldap, LdapConnAsync, Scope, SearchEntry, result::Result};
use ansi_term::Colour;
use serde::{Serialize, Deserialize};
use std::fs;
use clap::Parser;

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

    // config file
    #[clap(short, long, default_value = "vulnerable.json")]
    config: String,
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

        // add attributes and values to string
        for (name,attribute) in search_entry.attrs{
            output.push_str(&format!("{}: ",name));
            for value in attribute{
                output.push_str(&value);
            }
            output.push_str("\n");
        }
        output.push_str("\n");
    }
    return Ok(output);
}

async fn run_query(ldap: &mut Ldap, query: &Query) -> Result<String>{
    // run query
    let (rs, _res) = ldap.search(
        &query.base_dn,
        Scope::Subtree,
        &query.query,
        &query.attr
    ).await?.success()?;

    let output = resultentries_to_string(rs)?;

    // post processing on results
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
    let queries: Vec<Query> = serde_json::from_reader(config).expect("config.json should be proper JSON");

    // bind to ldap server
    let (conn, mut ldap) = LdapConnAsync::new(&format!("ldap://{}:389",args.host)).await?;
    ldap3::drive!(conn);
    let _ = ldap.simple_bind(&args.user, &args.pass).await?;

    // get base dn
    let dn = get_dn(&mut ldap).await?;
    
    // TODO: make asynchronous
    // TODO: custom queries, i.e: nested domain admins, computers with password last set
    for mut query in queries{
        println!("{}:", Colour::Purple.underline().bold().paint(&query.name));
        // println!("{}:", query.name);
        query.base_dn.push_str(&dn);
        let rs = run_query(&mut ldap, &query).await?;
        println!("{}", rs);
    }

    Ok(ldap.unbind().await?)
}