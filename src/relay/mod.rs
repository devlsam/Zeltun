pub mod direct;
pub mod pool;
pub mod socks5;
pub mod sni;

#[cfg(test)]
mod tests_stress;
#[cfg(test)]
mod tests_unit;
#[cfg(test)]
mod tests_sni;

pub use direct::*;
pub use pool::*;
pub use socks5::*;
pub use sni::*;

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

/// Relays TCP streams bidirectionally without extra allocation on idle connections.
pub async fn relay_tcp(c1: TcpStream, c2: TcpStream) -> std::io::Result<()> {
    relay_tcp_inner(c1, c2, None).await
}

/// Relays TCP streams bidirectionally while crediting transferred bytes to `counter`.
pub async fn relay_tcp_counted(c1: TcpStream, c2: TcpStream, counter: &'static AtomicU64) -> std::io::Result<()> {
    relay_tcp_inner(c1, c2, Some(counter)).await
}

async fn relay_tcp_inner(c1: TcpStream, c2: TcpStream, counter: Option<&'static AtomicU64>) -> std::io::Result<()> {
    let _ = c1.set_nodelay(true);
    let _ = c2.set_nodelay(true);

    let (r1, mut w1) = c1.into_split();
    let (r2, mut w2) = c2.into_split();

    let task1 = async {
        let res = copy_stream(&r1, &mut w2, counter).await;
        let _ = w2.shutdown().await;
        res
    };

    let task2 = async {
        let res = copy_stream(&r2, &mut w1, counter).await;
        let _ = w1.shutdown().await;
        res
    };

    tokio::pin!(task1);
    tokio::pin!(task2);

    tokio::select! {
        _ = &mut task1 => {
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut task2).await;
        }
        _ = &mut task2 => {
            let _ = tokio::time::timeout(Duration::from_secs(5), &mut task1).await;
        }
    }

    Ok(())
}

async fn copy_stream(
    reader: &OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    counter: Option<&AtomicU64>,
) -> std::io::Result<u64> {
    let mut total = 0u64;
    loop {
        reader.readable().await?;
        let mut buf = BUFFER_POOL.acquire();
        loop {
            match reader.try_read(&mut buf[..]) {
                Ok(0) => {
                    BUFFER_POOL.release(buf);
                    return Ok(total);
                }
                Ok(n) => {
                    total += n as u64;
                    if let Some(c) = counter {
                        c.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    if let Err(e) = writer.write_all(&buf[..n]).await {
                        BUFFER_POOL.release(buf);
                        return Err(e);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    BUFFER_POOL.release(buf);
                    return Err(e);
                }
            }
        }
        BUFFER_POOL.release(buf);
    }
}
