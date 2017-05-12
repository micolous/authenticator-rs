#[macro_use]
extern crate crypto;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
extern crate base64;
extern crate u2fhid;
use std::{io, thread, time};
use std::sync::mpsc::{channel, Sender, Receiver, RecvTimeoutError, TryRecvError};
use std::time::Duration;
use u2fhid::U2FDevice;

const PARAMETER_SIZE : usize = 32;

struct WorkUnit {
    timeout: Duration,
    challenge: Vec<u8>,
    application: Vec<u8>,
    key_handle: Option<Vec<u8>>,
    result_tx: Sender<io::Result<Vec<u8>>>,
    cancel_rx: Receiver<()>,
}

pub struct U2FManager {
}

impl U2FManager {
    pub fn new() -> U2FManager {
        U2FManager{}
    }

    // Cannot block.
    pub fn register<F>(&self, timeout_sec: u8, challenge: Vec<u8>, application: Vec<u8>, callback: F)
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            callback(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes")));
            return;
        }

        let timeout = Duration::from_secs(timeout_sec as u64);

        thread::Builder::new().name("Register Runloop".to_string()).spawn(move || {
            let mut manager = u2fhid::platform::new();
            let result = manager.register(timeout, challenge, application);
            callback(result);
        });
    }

    // Cannot block.
    pub fn sign<F>(&self, timeout_sec: u8, challenge: Vec<u8>, application: Vec<u8>, key_handle: Vec<u8>, callback: F)
        where F: FnOnce(io::Result<Vec<u8>>), F: Send + 'static
    {
        if challenge.len() != PARAMETER_SIZE || application.len() != PARAMETER_SIZE {
            callback(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid parameter sizes")));
            return;
        }

        let timeout = Duration::from_secs(timeout_sec as u64);

        thread::Builder::new().name("Sign Runloop".to_string()).spawn(move || {
            let mut manager = u2fhid::platform::new();
            let result = manager.sign(timeout, challenge, application, key_handle);
            callback(result);
        });
    }

    // Cannot block. Cancels a single operation.
    pub fn cancel<F>(&self) {
    }
}

fn u2f_get_key_handle_from_register_response(register_response: &Vec<u8>) -> io::Result<Vec<u8>>
{
    if register_response[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Reserved byte not set correctly"));
    }

    let key_handle_len = register_response[66] as usize;
    let mut public_key = register_response.clone();
    let mut key_handle = public_key.split_off(67);
    // let attestation = key_handle.split_off(key_handle_len);

    Ok(key_handle)
}

fn main() {
    println!("Searching for keys...");

    let mut challenge = Sha256::new();
    challenge.input_str(r#"{"challenge": "1vQ9mxionq0ngCnjD-wTsv1zUSrGRtFqG2xP09SbZ70", "version": "U2F_V2", "appId": "http://demo.yubico.com"}"#);
    let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
    challenge.result(&mut chall_bytes);

    let mut application = Sha256::new();
    application.input_str("http://demo.yubico.com");
    let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
    application.result(&mut app_bytes);

    let manager = U2FManager::new();

    let (reg_tx, reg_rx) = channel();
    manager.register(15, chall_bytes, app_bytes, move |reg_result| {
        // Ship back to the main thread
        if let Err(e) = reg_tx.send(reg_result) {
            panic!("Could not send: {}", e);
        }
    });

    let register_data = match reg_rx.recv().expect("Should not error on register receive") {
        Ok(v) => v,
        Err(e) => panic!("Register failure: {}", e),
    };

    println!("Register result: {}", base64::encode(&register_data));

    let key_handle = u2f_get_key_handle_from_register_response(&register_data).unwrap();

    let mut chall_bytes: Vec<u8> = vec![0; challenge.output_bytes()];
    challenge.result(&mut chall_bytes);
    let mut app_bytes: Vec<u8> = vec![0; application.output_bytes()];
    application.result(&mut app_bytes);

    let (sig_tx, sig_rx) = channel();
    manager.sign(15, chall_bytes, app_bytes, key_handle, move|sig_result| {
        // Ship back to the main thread
        if let Err(e) = sig_tx.send(sig_result) {
            panic!("Could not send: {}", e);
        }
    });

    let sign_data = match sig_rx.recv().expect("Should not error on signature receive") {
        Ok(v) => v,
        Err(e) => panic!("Sign failure: {}", e),
    };

    println!("Sign result: {}", base64::encode(&sign_data));

    println!("Done.");
}
