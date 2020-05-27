import secrets

from eth_typing import Address, Hash32

from eth_orm.constants import GENESIS_PARENT_HASH
from eth_orm.models import (
    Block,
    BlockTransaction,
    BlockUncle,
    Header,
    Log,
    LogTopic,
    Receipt,
    Topic,
    Transaction,
)
from eth_orm.session import Session

try:
    import factory
except ImportError as err:
    raise ImportError(
        "The `factory-boy` library is required to use the `alexandria.tools.factories` module"
    ) from err


def AddressFactory() -> Address:
    return Address(secrets.token_bytes(20))


def Hash32Factory() -> Hash32:
    return Hash32(secrets.token_bytes(32))


class HeaderFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = Header
        sqlalchemy_session = Session
        rename = {
            "bloom": "_bloom",
            "parent_hash": "_parent_hash",
            "detatched_parent_hash": "_detatched_parent_hash",
        }

    hash = factory.LazyFunction(Hash32Factory)

    is_canonical = True

    parent_hash = GENESIS_PARENT_HASH
    detatched_parent_hash = None

    uncles_hash = factory.LazyFunction(Hash32Factory)
    coinbase = factory.LazyFunction(AddressFactory)

    state_root = factory.LazyFunction(Hash32Factory)
    transaction_root = factory.LazyFunction(Hash32Factory)
    receipt_root = factory.LazyFunction(Hash32Factory)

    bloom = b""

    difficulty = b"\x01"
    block_number = 0
    gas_limit = 3141592
    gas_used = 3141592
    timestamp = 0
    extra_data = b""
    # mix_hash = factory.LazyFunction(Hash32Factory)
    nonce = factory.LazyFunction(lambda: secrets.token_bytes(8))

    @classmethod
    def from_parent(cls, parent: Header) -> Header:
        return cls(
            parent_hash=parent.hash,
            detatched_parent_hash=None,
            block_number=parent.block_number + 1,
        )


class BlockFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = Block
        sqlalchemy_session = Session

    header = factory.SubFactory(HeaderFactory)
    header_hash = factory.LazyAttribute(lambda obj: obj.header.hash)


class BlockUncleFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = BlockUncle
        sqlalchemy_session = Session

    idx = 0

    block = factory.SubFactory(BlockFactory)
    block_header_hash = factory.LazyAttribute(lambda obj: obj.block.header_hash)

    uncle = factory.SubFactory(HeaderFactory)
    uncle_hash = factory.LazyAttribute(lambda obj: obj.uncle.hash)


class TransactionFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = Transaction
        sqlalchemy_session = Session

    # TODO: Compute via RLP
    hash = factory.LazyFunction(Hash32Factory)

    nonce = 0
    gas_price = 1
    gas = 21000
    to = factory.LazyFunction(AddressFactory)
    value = b"\x00"
    data = b""
    v = b"\x00" * 32
    r = b"\x00" * 32
    s = b"\x00" * 32

    sender = factory.LazyFunction(AddressFactory)


class BlockTransactionFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = BlockTransaction
        sqlalchemy_session = Session

    idx = 0

    block = factory.SubFactory(BlockFactory)
    block_header_hash = factory.LazyAttribute(lambda obj: obj.block.header_hash)

    transaction = factory.SubFactory(TransactionFactory)
    transaction_hash = factory.LazyAttribute(lambda obj: obj.transaction.hash)


class ReceiptFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = Receipt
        sqlalchemy_session = Session
        rename = {"bloom": "_bloom"}

    blocktransaction = factory.SubFactory(BlockTransactionFactory)
    transaction_hash = factory.LazyAttribute(
        lambda obj: obj.blocktransaction.transaction_hash
    )
    block_header_hash = factory.LazyAttribute(
        lambda obj: obj.blocktransaction.block_header_hash
    )

    state_root = factory.LazyFunction(Hash32Factory)
    bloom = b""
    gas_used = 21000


class LogFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = Log
        sqlalchemy_session = Session

    idx = 0
    receipt = factory.SubFactory(ReceiptFactory)
    transaction_hash = factory.LazyAttribute(lambda obj: obj.receipt.transaction_hash)
    block_header_hash = factory.LazyAttribute(lambda obj: obj.receipt.block_header_hash)

    address = factory.LazyFunction(AddressFactory)
    data = b""


class TopicFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = Topic
        sqlalchemy_session = Session

    topic = factory.LazyFunction(Hash32Factory)


class LogTopicFactory(factory.alchemy.SQLAlchemyModelFactory):  # type: ignore
    class Meta:
        model = LogTopic
        sqlalchemy_session = Session

    idx = 0

    topic = factory.SubFactory(TopicFactory)
    topic_topic = factory.LazyAttribute(lambda obj: obj.topic.topic)

    log = factory.SubFactory(LogFactory)
    log_idx = factory.LazyAttribute(lambda obj: obj.log.idx)
    log_transaction_hash = factory.LazyAttribute(lambda obj: obj.log.transaction_hash)
    log_block_header_hash = factory.LazyAttribute(lambda obj: obj.log.block_header_hash)
