


mod llmnr;

fn main() {


    let ip = llmnr::search_until_responder_found();
    println!("Found Responder at: {}", ip.ip());
    
}
