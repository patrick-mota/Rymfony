#[allow(unused_imports)]

use crate::http::fastcgi_handler::handle_fastcgi;

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use console::style;
use hyper::server::conn::AddrStream;
use hyper::server::conn::AddrIncoming;
use hyper::service::make_service_fn;
use hyper::service::service_fn;
use hyper::Body;
use hyper::Request;
use hyper::Response;
use hyper::Server;
use hyper_staticfile::Static;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_native_tls::native_tls::TlsAcceptor;
use tokio_native_tls::native_tls::Identity;
use warp::{Filter, method};
use http::Method;
use http::HeaderMap;
use warp::filters::path::FullPath;
use warp::filters::header::headers_cloned;
use tokio::stream::Stream;
use std::collections::HashMap;
use hyper::body::Bytes;

#[tokio::main]
pub(crate) async fn start(
    http_port: u16,
    php_port: u16,
    document_root: String,
    php_entrypoint_file: String,
) {
    /*
    // Bind the server's socket
    let addr = "127.0.0.1:12345".to_string();
    let mut tcp: TcpListener = TcpListener::bind(&addr).await?;

    // Create the TLS acceptor.
    let der = include_bytes!("identity.p12");
    let cert = Identity::from_pkcs12(der, "mypass")?;
    let tls_acceptor = TlsAcceptor::builder(cert).build()?;
    loop {
        // Asynchronously wait for an inbound socket.
        let (socket, remote_addr) = tcp.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        println!("accept connection from {}", remote_addr);
        tokio::spawn(async move {
            // Accept the TLS connection.
            let mut tls_stream = tls_acceptor.accept(socket).await.expect("accept error");
            // In a loop, read data from the socket and write the data back.

            let mut buf = [0; 1024];
            let n = tls_stream
                .read(&mut buf)
                .await
                .expect("failed to read data from socket");

            if n == 0 {
                return;
            }
            tls_stream
                .write_all(&buf[0..n])
                .await
                .expect("failed to write data to socket");
        });
    }

    let http_addr: SocketAddr = SocketAddr::from(([127, 0, 0, 1], http_port));
    let static_files_server = Static::new(Path::new(&document_root));

    let document_root = document_root.clone();
    let php_entrypoint_file = php_entrypoint_file.clone();

    let make_service = make_service_fn(move |socket: &AddrStream| {
        let remote_addr = socket.remote_addr();
        let document_root = document_root.clone();
        let php_entrypoint_file = php_entrypoint_file.clone();
        let static_files_server = static_files_server.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
                let document_root = document_root.clone();
                let php_entrypoint_file = php_entrypoint_file.clone();
                let static_files_server = static_files_server.clone();
                async move {
                    let request_uri = req.uri();
                    let request_path = request_uri.path();

                    let http_version = crate::http::version::as_str(req.version());

                    let render_static = get_render_static_path(&document_root, &request_path);
                    let render_static = !request_path.contains(".php")
                        && render_static != ""
                        && request_path != ""
                        && request_path != "/";

                    info!(
                        "{} {} {}{}",
                        http_version,
                        style(req.method()).yellow(),
                        style(request_uri).cyan(),
                        if render_static { " (static)" } else { "" }
                    );

                    if render_static {
                        return serve_static(req, static_files_server.clone()).await;
                    }

                    trace!("Forwarding to FastCGI");

                    return handle_fastcgi(
                        document_root.clone(),
                        php_entrypoint_file.clone(),
                        remote_addr.clone(),
                        req,
                        http_port,
                        php_port,
                    )
                    .await;
                }
            }))
        }
    });

    let http_server = Server::builder(AddrIncoming::bind(&http_addr).unwrap_or_else(|e| {
        panic!("error binding to {}: {}", http_addr, e);
    }))
        .serve(make_service);
    */

    let routes = warp::any()
        .and(method())
        .and(warp::path::full())
        .and(warp::query::<HashMap<String, String>>())
        .and(headers_cloned())
        .and(warp::body::bytes())
        .map(|method: Method, path: FullPath, query: HashMap<String, String>, headers: HeaderMap, body: Bytes| {
            dbg!(method);
            dbg!(path);
            dbg!(query);
            dbg!(headers);
            dbg!(body);
            "Hello!"
        })
    ;

    warp::serve(routes).run(([127, 0, 0, 1], http_port)).await;
    // http_server.await.unwrap();
}

async fn serve_static(
    req: Request<Body>,
    static_files_server: Static,
) -> anyhow::Result<Response<Body>> {
    let static_files_server = static_files_server.clone();
    let response_future = static_files_server.serve(req);

    let response = response_future.await;

    anyhow::Result::Ok(response.unwrap())
}

fn get_render_static_path(document_root: &str, request_path: &str) -> String {
    let directory_separators: &[_] = &['/', '\\'];
    let request_path = request_path.trim_start_matches(directory_separators);
    let document_root = document_root.trim_end_matches(directory_separators);

    let static_doc_root = PathBuf::from(&document_root);

    let docroot_path = PathBuf::from(&static_doc_root).join(request_path);

    let docroot_public_path = PathBuf::from(&static_doc_root)
        .join("public")
        .join(request_path);

    let docroot_web_path = PathBuf::from(&static_doc_root)
        .join("web")
        .join(request_path);

    let mut render_static: &str = "";

    if docroot_path.is_file() {
        render_static = docroot_path.to_str().unwrap();
        debug!("Static file {} found in document root.", &render_static);
    } else if docroot_public_path.is_file() {
        render_static = docroot_public_path.to_str().unwrap();
        debug!("Static file {} found in \"public/\" subdirectory.", &render_static);
    } else if docroot_web_path.is_file() {
        debug!("Static file {} found in \"web/\" subdirectory.", &render_static);
        render_static = docroot_web_path.to_str().unwrap();
    } else {
        debug!("No static file found based on \"{}\" path.", request_path);
    }

    String::from(render_static)
}
