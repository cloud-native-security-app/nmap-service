//! Capa de mensajería con el Broker. Aísla la tecnología concreta de cola de
//! mensajes tras los traits [`consumer::ScanRequestSource`] (entrada de
//! solicitudes) y [`publisher::ScanResultSink`] (salida de desenlaces), de modo
//! que el resto del servicio no la conozca.

pub mod consumer;
pub mod publisher;
