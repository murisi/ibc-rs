use core::marker::{Send, Sync};
use std::convert::{TryFrom, TryInto};
#[cfg(feature = "borsh")]
use std::io::{ErrorKind, Write};

#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};
use chrono::{DateTime, Utc};
use prost_types::Any;
use serde::Serialize;
use tendermint_proto::Protobuf;

use ibc_proto::ibc::core::client::v1::ConsensusStateWithHeight;

use crate::events::IbcEventType;
use crate::ics02_client::client_type::ClientType;
use crate::ics02_client::error::{Error, Kind};
use crate::ics02_client::height::Height;
use crate::ics07_tendermint::consensus_state;
use crate::ics23_commitment::commitment::CommitmentRoot;
use crate::ics24_host::identifier::ClientId;
use crate::timestamp::Timestamp;
use crate::utils::UnwrapInfallible;

#[cfg(any(test, feature = "mocks"))]
use crate::mock::client_state::MockConsensusState;

pub const TENDERMINT_CONSENSUS_STATE_TYPE_URL: &str =
    "/ibc.lightclients.tendermint.v1.ConsensusState";

pub const MOCK_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.mock.ConsensusState";

#[dyn_clonable::clonable]
pub trait ConsensusState: Clone + std::fmt::Debug + Send + Sync {
    /// Type of client associated with this consensus state (eg. Tendermint)
    fn client_type(&self) -> ClientType;

    /// Commitment root of the consensus state, which is used for key-value pair verification.
    fn root(&self) -> &CommitmentRoot;

    /// Performs basic validation of the consensus state
    fn validate_basic(&self) -> Result<(), Box<dyn std::error::Error>>;

    /// Wrap into an `AnyConsensusState`
    fn wrap_any(self) -> AnyConsensusState;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum AnyConsensusState {
    Tendermint(consensus_state::ConsensusState),

    #[cfg(any(test, feature = "mocks"))]
    Mock(MockConsensusState),
}

impl AnyConsensusState {
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Self::Tendermint(cs_state) => {
                let date: DateTime<Utc> = cs_state.timestamp.into();
                Timestamp::from_datetime(date)
            }

            #[cfg(any(test, feature = "mocks"))]
            Self::Mock(mock_state) => mock_state.timestamp(),
        }
    }

    pub fn client_type(&self) -> ClientType {
        match self {
            AnyConsensusState::Tendermint(_cs) => ClientType::Tendermint,

            #[cfg(any(test, feature = "mocks"))]
            AnyConsensusState::Mock(_cs) => ClientType::Mock,
        }
    }
}

#[cfg(feature = "borsh")]
impl BorshSerialize for AnyConsensusState {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let vec = self
            .encode_vec()
            .expect("AnyConsensusState encoding shouldn't fail");
        writer.write_all(&vec)
    }
}

#[cfg(feature = "borsh")]
impl BorshDeserialize for AnyConsensusState {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let result = AnyConsensusState::decode_vec(buf).map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding AnyConsensusState: {}", e),
            )
        });
        *buf = &[];
        result
    }
}

impl Protobuf<Any> for AnyConsensusState {}

impl TryFrom<Any> for AnyConsensusState {
    type Error = Error;

    fn try_from(value: Any) -> Result<Self, Self::Error> {
        match value.type_url.as_str() {
            "" => Err(Kind::EmptyConsensusStateResponse.into()),

            TENDERMINT_CONSENSUS_STATE_TYPE_URL => Ok(AnyConsensusState::Tendermint(
                consensus_state::ConsensusState::decode_vec(&value.value)
                    .map_err(|e| Kind::InvalidRawConsensusState.context(e))?,
            )),

            #[cfg(any(test, feature = "mocks"))]
            MOCK_CONSENSUS_STATE_TYPE_URL => Ok(AnyConsensusState::Mock(
                MockConsensusState::decode_vec(&value.value)
                    .map_err(|e| Kind::InvalidRawConsensusState.context(e))?,
            )),

            _ => Err(Kind::UnknownConsensusStateType(value.type_url).into()),
        }
    }
}

impl From<AnyConsensusState> for Any {
    fn from(value: AnyConsensusState) -> Self {
        match value {
            AnyConsensusState::Tendermint(value) => Any {
                type_url: TENDERMINT_CONSENSUS_STATE_TYPE_URL.to_string(),
                value: value
                    .encode_vec()
                    .expect("encoding to `Any` from `AnyConsensusState::Tendermint`"),
            },
            #[cfg(any(test, feature = "mocks"))]
            AnyConsensusState::Mock(value) => Any {
                type_url: MOCK_CONSENSUS_STATE_TYPE_URL.to_string(),
                value: value
                    .encode_vec()
                    .expect("encoding to `Any` from `AnyConsensusState::Mock`"),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AnyConsensusStateWithHeight {
    pub height: Height,
    pub consensus_state: AnyConsensusState,
}

impl Protobuf<ConsensusStateWithHeight> for AnyConsensusStateWithHeight {}

impl TryFrom<ConsensusStateWithHeight> for AnyConsensusStateWithHeight {
    type Error = Kind;

    fn try_from(value: ConsensusStateWithHeight) -> Result<Self, Self::Error> {
        let state = value
            .consensus_state
            .map(AnyConsensusState::try_from)
            .transpose()
            .map_err(|_| Kind::InvalidRawConsensusState)?
            .ok_or(Kind::EmptyConsensusStateResponse)?;

        Ok(AnyConsensusStateWithHeight {
            height: value
                .height
                .ok_or(Kind::MissingHeight)?
                .try_into()
                .unwrap_infallible(),
            consensus_state: state,
        })
    }
}

impl From<AnyConsensusStateWithHeight> for ConsensusStateWithHeight {
    fn from(value: AnyConsensusStateWithHeight) -> Self {
        ConsensusStateWithHeight {
            height: Some(value.height.into()),
            consensus_state: Some(value.consensus_state.into()),
        }
    }
}

impl ConsensusState for AnyConsensusState {
    fn client_type(&self) -> ClientType {
        self.client_type()
    }

    fn root(&self) -> &CommitmentRoot {
        match self {
            Self::Tendermint(cs_state) => cs_state.root(),

            #[cfg(any(test, feature = "mocks"))]
            Self::Mock(mock_state) => mock_state.root(),
        }
    }

    fn validate_basic(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Tendermint(cs_state) => cs_state.validate_basic(),

            #[cfg(any(test, feature = "mocks"))]
            Self::Mock(mock_state) => mock_state.validate_basic(),
        }
    }

    fn wrap_any(self) -> AnyConsensusState {
        self
    }
}

/// Query request for a single client event, identified by `event_id`, for `client_id`.
#[derive(Clone, Debug)]
pub struct QueryClientEventRequest {
    pub height: crate::Height,
    pub event_id: IbcEventType,
    pub client_id: ClientId,
    pub consensus_height: crate::Height,
}
