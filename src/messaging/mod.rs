//! Capa de mensajería con el Broker. Aísla la tecnología concreta de cola de
//! mensajes tras los traits `consumer::ScanRequestSource` y
//! `publisher::ScanResultSink`, de modo que el resto del servicio no la conozca.
//!
//! Stub del scaffolding: las implementaciones reales son las features
//! `broker_consumer` y `broker_publisher`.

pub mod consumer;
pub mod publisher;
