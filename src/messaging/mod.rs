//! Capa de mensajería con el Broker. Aísla la tecnología concreta de cola de
//! mensajes tras los traits [`consumer::ScanRequestSource`] (entrada de
//! solicitudes) y [`publisher::ScanResultSink`] (salida de desenlaces), de modo
//! que el resto del servicio no la conozca.
//!
//! [`rabbitmq`] añade el adaptador real (`lapin` sobre AMQPS, feature
//! `broker_adapter`): [`rabbitmq::RabbitMqScanRequestSource`],
//! [`rabbitmq::RabbitMqScanCancellationSource`] y
//! [`rabbitmq::RabbitMqScanResultSink`] implementan los mismos traits que los
//! stubs en memoria de [`consumer`]/[`publisher`] — el resto del servicio
//! (`pipeline`, `wiring`) sigue sin conocer que la tecnología es RabbitMQ.

pub mod consumer;
pub mod publisher;
pub mod rabbitmq;
