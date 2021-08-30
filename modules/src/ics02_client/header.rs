use std::convert::TryFrom;
#[cfg(feature = "borsh")]
use std::io::{ErrorKind, Write};

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use prost_types::Any;
use serde_derive::{Deserialize, Serialize};
use tendermint_proto::Protobuf;

use crate::ics02_client::client_type::ClientType;
use crate::ics02_client::error::{Error, Kind};
use crate::ics07_tendermint::header::Header as TendermintHeader;
#[cfg(any(test, feature = "mocks"))]
use crate::mock::header::MockHeader;
use crate::Height;

pub const TENDERMINT_HEADER_TYPE_URL: &str = "/ibc.lightclients.tendermint.v1.Header";
pub const MOCK_HEADER_TYPE_URL: &str = "/ibc.mock.Header";

/// Abstract of consensus state update information
#[dyn_clonable::clonable]
pub trait Header: Clone + std::fmt::Debug + Send + Sync {
    /// The type of client (eg. Tendermint)
    fn client_type(&self) -> ClientType;

    /// The height of the consensus state
    fn height(&self) -> Height;

    /// Wrap into an `AnyHeader`
    fn wrap_any(self) -> AnyHeader;
}

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)] // TODO: Add Eq bound once possible
#[allow(clippy::large_enum_variant)]
pub enum AnyHeader {
    Tendermint(TendermintHeader),

    #[cfg(any(test, feature = "mocks"))]
    Mock(MockHeader),
}

impl Header for AnyHeader {
    fn client_type(&self) -> ClientType {
        match self {
            Self::Tendermint(header) => header.client_type(),

            #[cfg(any(test, feature = "mocks"))]
            Self::Mock(header) => header.client_type(),
        }
    }

    fn height(&self) -> Height {
        match self {
            Self::Tendermint(header) => header.height(),

            #[cfg(any(test, feature = "mocks"))]
            Self::Mock(header) => header.height(),
        }
    }

    fn wrap_any(self) -> AnyHeader {
        self
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for AnyHeader {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec = self
            .encode_vec()
            .expect("AnyHeader encoding shouldn't fail");
        writer.write_all(&vec)
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for AnyHeader {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        AnyHeader::decode_vec(buf).map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding AnyHeader: {}", e),
            )
        })
    }
}

impl Protobuf<Any> for AnyHeader {}

impl TryFrom<Any> for AnyHeader {
    type Error = Error;

    fn try_from(raw: Any) -> Result<Self, Self::Error> {
        match raw.type_url.as_str() {
            TENDERMINT_HEADER_TYPE_URL => Ok(AnyHeader::Tendermint(
                TendermintHeader::decode_vec(&raw.value)
                    .map_err(|e| Kind::InvalidRawHeader.context(e))?,
            )),

            #[cfg(any(test, feature = "mocks"))]
            MOCK_HEADER_TYPE_URL => Ok(AnyHeader::Mock(
                MockHeader::decode_vec(&raw.value)
                    .map_err(|e| Kind::InvalidRawHeader.context(e))?,
            )),

            _ => Err(Kind::UnknownHeaderType(raw.type_url).into()),
        }
    }
}

impl From<AnyHeader> for Any {
    fn from(value: AnyHeader) -> Self {
        match value {
            AnyHeader::Tendermint(header) => Any {
                type_url: TENDERMINT_HEADER_TYPE_URL.to_string(),
                value: header
                    .encode_vec()
                    .expect("encoding to `Any` from `AnyHeader::Tendermint`"),
            },
            #[cfg(any(test, feature = "mocks"))]
            AnyHeader::Mock(header) => Any {
                type_url: MOCK_HEADER_TYPE_URL.to_string(),
                value: header
                    .encode_vec()
                    .expect("encoding to `Any` from `AnyHeader::Mock`"),
            },
        }
    }
}
