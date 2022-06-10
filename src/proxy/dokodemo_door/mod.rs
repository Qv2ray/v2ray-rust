use crate::common::new_error;
use crate::config::DokodemoDoor;
use crate::proxy::Address;
use libc::c_int;
use std::mem;
use std::net::{SocketAddr, TcpListener};
#[cfg(unix)]
use std::os::unix::io::AsRawFd;

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) ) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == -1 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[cfg(unix)]
pub(crate) unsafe fn setsockopt<T>(
    fd: c_int,
    opt: c_int,
    val: c_int,
    payload: T,
) -> std::io::Result<()> {
    let payload = &payload as *const T as *const libc::c_void;
    syscall!(setsockopt(
        fd,
        opt,
        val,
        payload,
        mem::size_of::<T>() as libc::socklen_t,
    ))
    .map(|_| ())
}

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
        log::info!("set tproxy to {}", door.tproxy);
        socket.set_reuse_address(true)?;
        if domain == socket2::Domain::IPV6 {
            unsafe {
                setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_IPV6,
                    libc::IPV6_TRANSPARENT,
                    door.tproxy as c_int,
                )?;
            }
        } else {
            socket.set_ip_transparent(door.tproxy)?;
        }
    }
    let addr = door.addr.get_sock_addr().into();
    socket.bind(&addr)?;
    socket.listen(backlog as c_int)?;
    let std_listener = TcpListener::from(socket);
    Ok(std_listener)
}
