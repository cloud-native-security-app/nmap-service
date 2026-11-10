//! Capa de mensajería. Aísla la tecnología concreta de cola de mensajes tras
//! los traits [`consumer::ScanRequestSource`] (entrada de solicitudes),
//! [`consumer::ScanCancellationSource`] (entrada de cancelaciones) y
//! [`publisher::ScanResultSink`] (salida de desenlaces), de modo que el resto
//! del servicio no la conozca.
//!
//! Los adaptadores reales usan el SDK de AWS: [`sqs`] consume las colas SQS de
//! solicitudes y cancelaciones y [`sns`] publica los desenlaces en el topic SNS
//! `scan-outcomes`. [`kinesis`] publica los eventos de seguridad (feature
//! `security_event_publisher`) en el stream `security-events`; no implementa
//! esos traits sino el puerto [`crate::security_events::SecurityEventPublisher`].
//! Los adaptadores SQS/SNS implementan los mismos traits que los stubs en
//! memoria de [`consumer`]/[`publisher`] — el resto del servicio (`pipeline`,
//! `wiring`) no sabe que la tecnología es SQS/SNS/Kinesis.

pub mod consumer;
pub mod kinesis;
pub mod publisher;
pub mod sns;
pub mod sqs;
