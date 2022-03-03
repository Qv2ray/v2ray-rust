use crate::common::new_error;
use crate::config::DokodemoDoor;
use crate::proxy::Address;
use libc::c_int;
use log::info;
use std::net::{SocketAddr, TcpListener};

pub(crate) fn build_dokodemo_door_listener(
    door: &mut DokodemoDoor,
    backlog: u32,
) -> std::io::Result<TcpListener> {
    let domain = match door.addr {
        Address::SocketAddress(SocketAddr::V4(_)) => socket2::Domain::IPV4,
        Address::SocketAddress(SocketAddr::V6(_)) => socket2::Domain::IPV6,
        Address::DomainNameAddress(_, _) => {
            return Err(new_error("unsupported dokodemo door listen addr type."));
        }
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    #[cfg(target_os = "linux")]
    {
        info!("set tproxy to {}", door.tproxy);
        socket.set_reuse_address(true)?;
        socket.set_ip_transparent(door.tproxy)?;
    }
    let addr = door.addr.get_sock_addr().into();
    socket.bind(&addr)?;
    socket.listen(backlog as c_int)?;
    let std_listener = TcpListener::from(socket);
    Ok(std_listener)
}
