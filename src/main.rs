pub mod cap_table;
pub mod capabilities;
pub mod object;
pub mod packet_types;
pub mod service;

use log::*;
use simple_logger::SimpleLogger;

use clap::Parser;

use crate::service::tcap::*;

#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
struct Config {
    /// The Network Interface to bind
    #[arg(short, long)]
    interface: String,

    /// Address to bind to (including port number)
    #[arg(short, long)]
    address: String,

    /// Address of the switch control plane (including port number)
    #[arg(short, long)]
    switch_addr: String,
}

impl Config {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            address: self.address.clone(),
            switch_addr: self.switch_addr.clone(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    SimpleLogger::new().init().unwrap();

    let conf: Config = Config::parse();
    let service = Service::new(conf.clone()).await;
    let s = service.clone();
    let service_handle = tokio::spawn(async move {
        debug!("starting service thread");
        let _ = s.run().await.unwrap();
    });

    debug!("starting tcap-rs main");
    service_handle.await.unwrap();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use log::debug;
    use simple_logger::SimpleLogger;
    use tokio::sync::Mutex;

    use crate::{
        capabilities::tcap::CapType,
        object::tcap::object::RequestObject,
        packet_types::tcap::IpAddress,
        service::tcap::Service,
        Config,
    };

    #[tokio::test]
    async fn test_delegate() {
        let service1_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1331".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service1 = Service::new(service1_conf.clone()).await;
        let s = service1.clone();
        let service1_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });

        let service2_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1330".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service2 = Service::new(service2_conf.clone()).await;
        let s = service2.clone();
        let service2_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });

        assert!(
            service1.cap_table.get_capids().await.is_empty(),
            "Service1 CapTable should be empty at start"
        );
        assert!(
            service2.cap_table.get_capids().await.is_empty(),
            "Service2 CapTable should be empty at start"
        );

        let c1 = service1.create_capability().await;
        assert!(
            service1
                .cap_table
                .get_capids()
                .await
                .contains(&c1.lock().await.cap_id),
            "Captable should contain ID of newly created cap"
        );
        debug!("created cap c1: {:?}", c1);
        let _ = c1
            .lock()
            .await
            .delegate(service1, IpAddress::from("10.0.0.9:1330"))
            .await;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(
            service2
                .cap_table
                .get_capids()
                .await
                .contains(&c1.lock().await.cap_id),
            "After delegate, service2 should have the capid in its table"
        );

        service1_handle.abort();
        service2_handle.abort();
    }

    #[tokio::test]
    async fn test_revocation() {
        SimpleLogger::new().init().unwrap();
        let service1_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1230".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service1 = Service::new(service1_conf.clone()).await;
        let s = service1.clone();
        let service1_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });

        let service2_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1231".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service2 = Service::new(service2_conf.clone()).await;
        let s = service2.clone();
        let service2_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });

        assert!(
            service1.cap_table.get_capids().await.is_empty(),
            "Service1 CapTable should be empty at start"
        );
        assert!(
            service2.cap_table.get_capids().await.is_empty(),
            "Service2 CapTable should be empty at start"
        );

        let c1 = service1.create_capability().await;
        assert!(
            service1
                .cap_table
                .get_capids()
                .await
                .contains(&c1.lock().await.cap_id),
            "Captable should contain ID of newly created cap"
        );
        debug!("created cap c1: {:?}", c1);
        let _ = c1
            .lock()
            .await
            .delegate(service1.clone(), IpAddress::from("10.0.0.9:1231"))
            .await;
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(
            service2
                .cap_table
                .get_capids()
                .await
                .contains(&c1.lock().await.cap_id),
            "After delegate, service2 should have the capid in its table"
        );

        c1.lock().await.revoke(service1.clone()).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(
            !service2
                .cap_table
                .get_capids()
                .await
                .contains(&c1.lock().await.cap_id),
            "After revoke, service2 should NOT have the capid in its table"
        );

        service1_handle.abort();
        service2_handle.abort();
    }

    #[tokio::test]
    async fn test_delegate_and_request_invocation() {
        SimpleLogger::new().init().unwrap();

        let service1_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1230".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service1 = Service::new(service1_conf.clone()).await;
        let s = service1.clone();
        let service1_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });

        let service2_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1231".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service2 = Service::new(service2_conf.clone()).await;
        let s2 = service2.clone();
        let service2_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s2.run().await.unwrap();
        });

        debug!("Creating Request Capability");
        let mut request_cap1 = service1.create_capability().await;
        request_cap1.lock().await.cap_type = CapType::Request;

        debug!("Creating Request Object");
        let request_object = Arc::new(Mutex::new(
            RequestObject::new(Box::new(move || {
                debug!("Executing Request Lambda");
                assert!(true, "request lambda must be executed");

                Ok(())
            }))
            .await,
        ));

        debug!("Binding Object to Cap");
        request_cap1.lock().await.bind(request_object).await;

        let _ = request_cap1
            .lock()
            .await
            .delegate(service1.clone(), IpAddress::from("10.0.0.9:1231"))
            .await;

        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        assert!(
            service2
                .cap_table
                .get_capids()
                .await
                .contains(&request_cap1.lock().await.cap_id),
            "After delegate, service2 should have the capid in its table"
        );

        let request_cap2 = service2
            .cap_table
            .get(request_cap1.lock().await.cap_id)
            .await
            .unwrap();

        debug!("service1 captab: {:?}", service1.cap_table);
        debug!("service2 captab: {:?}", service2.cap_table);

        debug!("Invoke ReqCap");
        request_cap2
            .lock()
            .await
            .request_invoke(service2)
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        service1_handle.abort();
        service2_handle.abort();
    }

    #[tokio::test]
    async fn test_local_request_invocation() {
        SimpleLogger::new().init().unwrap();

        let service1_conf = Config {
            interface: "veth250".to_string(),
            address: "10.0.0.9:1230".to_string(),
            switch_addr: "10.0.0.1".to_string(),
        };
        let service1 = Service::new(service1_conf.clone()).await;
        let s = service1.clone();
        let service1_handle = tokio::spawn(async move {
            debug!("starting service thread");
            let _ = s.run().await.unwrap();
        });

        debug!("Creating Request Capability");
        let mut request_cap = service1.create_capability().await;
        request_cap.lock().await.cap_type = CapType::Request;

        debug!("Creating Request Object");
        let request_object = Arc::new(Mutex::new(
            RequestObject::new(Box::new(move || {
                debug!("Executing Request Lambda");
                assert!(false, "request lambda must be executed");

                Ok(())
            }))
            .await,
        ));

        debug!("Binding Object to Cap");
        request_cap.lock().await.bind(request_object).await;

        debug!("Invoce ReqCap");
        request_cap
            .lock()
            .await
            .request_invoke(service1)
            .await
            .unwrap();

        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        service1_handle.abort();
    }
}
