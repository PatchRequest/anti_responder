


use std::thread;

use rand::Rng;
mod llmnr;

fn main() {

    let mut rng = rand::thread_rng();   
    let id: u16 = rng.gen();
    let handler = thread::spawn(move || {
        llmnr::await_response(&id);
    });

    let a_package = llmnr::generate(&id);
    let result = llmnr::send_request(a_package);
    match result {
        Ok(_) => println!("Sent request"),
        Err(e) => println!("Error sending request: {}", e),
    }
    
    handler.join().unwrap();
    println!("Done")
    


}
