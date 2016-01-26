#[cfg(feature = "ssl")] extern crate openssl;
#[cfg(feature = "ssl")] pub use openssl::ssl::{Ssl,SslContext, SslMethod, SslStream};
#[cfg(feature = "ssl")] pub use openssl::ssl::error::SslError;
pub use std::io::{BufReader, Read, BufRead, BufWriter, Write};
pub use std::net::TcpStream;
pub use std::fmt;


pub struct UnsecureConnection
{
    stream: TcpStream,
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>
}

impl UnsecureConnection
{
    pub fn new(host: &str, port: u16) -> UnsecureConnection
    {
        let stream = match TcpStream::connect((host, port))
        {
            Ok(sock) => sock,
            Err(err) => panic!("Failed to create socket in UnsecureConnection constructor. Exiting.")
        };
        let mut reader = BufReader::new(stream.try_clone().ok().expect("Failed to clone socket for BufReader in Connection constructor!"));
        let mut writer = BufWriter::new(stream.try_clone().ok().expect("Failed to clone socket for BufWriter in Connection constructor!"));
        UnsecureConnection{ stream: stream, reader: reader, writer: writer}
    }
    pub fn send(&mut self, to_send: &str)
    {
        self.writer.write_fmt(format_args!("{}\r\n", to_send));
        self.writer.flush();
    }
    pub fn read(&mut self) -> Option<String>
    {
        let mut buf = String::new();
        let bytes = match self.reader.read_line(&mut buf)
        {
            Ok(x) => x,
            Err(_) => 0,
        };
        if bytes == 0
        {
            return None
        } else
        {
            Some(buf)
        }
    }

}

#[cfg(feature = "ssl")]
pub struct SSLConnection
{
    ssl_stream: SslStream<TcpStream>,
    reader: BufReader<SslStream<TcpStream>>,
    writer: BufWriter<SslStream<TcpStream>>
}

#[cfg(feature = "ssl")]
impl SSLConnection
{
    pub fn new(host: &str, port: u16) -> SSLConnection
    {
        let stream = match TcpStream::connect((host, port))
        {
            Ok(sock) => sock,
            Err(err) => panic!("Failed to create socket in SSLConnection constructor! Exiting.")
        };
        let ssl_context = SslContext::new(SslMethod::Tlsv1).ok().expect("Failed to create SslContext in SSLConnection constructor!");
        let ssl = Ssl::new(&ssl_context).ok().expect("Failed to create Ssl in SSLConnection constructor!");
        let ssl_stream = SslStream::connect(ssl,stream).ok().expect("Failed to create SslStream in SSLConnection constructor!");
        let mut reader = BufReader::new(ssl_stream.try_clone().ok().expect("Failed to create reader for SSLConnection in SSLConnection constructor!"));
        let mut writer = BufWriter::new(ssl_stream.try_clone().ok().expect("Failed to create writer for SSLConnection in SSLConnection constructor!"));
        SSLConnection{ ssl_stream: ssl_stream, reader: reader, writer: writer}
    }
    pub fn send(&mut self, to_send: &str)
    {
        self.writer.write_fmt(format_args!("{}\r\n", to_send)).ok().expect("Bytes not written!");
        self.writer.flush();
    }
    pub fn read(&mut self) -> Option<String> 
    {
        let mut buf = String::new();
        let bytes = match self.reader.read_line(&mut buf)
        {
            Ok(x) => x,
            Err(_) => 0,
        };
        if bytes == 0
        {
            return None
        } else
        {
            Some(buf)
        }
    }

}

