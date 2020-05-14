from typing import Optional

from eth_typing import Hash32
from eth_utils import big_endian_to_int, humanize_hash, int_to_big_endian
from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    UniqueConstraint,
    and_,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref, relationship

from eth_orm.constants import GENESIS_PARENT_HASH
from eth_orm.session import Session

Base = declarative_base()


class BlockUncle(Base):
    query = Session.query_property()

    __tablename__ = "blockuncle"
    __table_args__ = (
        Index(
            "ix_blockuncle_idx_block_header_hash",
            "idx",
            "block_header_hash",
            unique=True,
        ),
        Index(
            "ix_block_header_hash_uncle_hash",
            "block_header_hash",
            "uncle_hash",
            unique=True,
        ),
        CheckConstraint("idx >= 0", name="_idx_positive"),
    )

    idx = Column(Integer, nullable=False)

    block_header_hash = Column(
        LargeBinary(32), ForeignKey("block.header_hash"), primary_key=True
    )
    uncle_hash = Column(LargeBinary(32), ForeignKey("header.hash"), primary_key=True)

    block = relationship("Block")
    uncle = relationship("Header")


class Header(Base):
    query = Session.query_property()

    __tablename__ = "header"
    __table_args__ = (
        CheckConstraint(
            "_parent_hash is null or _detatched_parent_hash is null",
            name="_no_double_parent_hash",
        ),
        CheckConstraint("block_number >= 0", name="_block_number_positive"),
        CheckConstraint("gas_limit >= 0", name="_gas_limit_positive"),
        CheckConstraint("gas_used >= 0", name="_gas_used_positive"),
        CheckConstraint("difficulty >= 0", name="_difficulty_positive"),
        CheckConstraint("timestamp >= 0", name="_timestamp_positive"),
        Index("ix_hash_is_canonical", "hash", "is_canonical"),
        Index(
            "ix_parent_hash_detatched_parent_hash",
            "_parent_hash",
            "_detatched_parent_hash",
        ),
    )

    hash = Column(LargeBinary(32), primary_key=True)

    block = relationship("Block", uselist=False, back_populates="header")
    uncle_blocks = relationship(
        "Block", secondary="blockuncle", order_by=BlockUncle.idx
    )

    is_canonical = Column(Boolean, nullable=False, index=True)

    _detatched_parent_hash = Column(LargeBinary(32), nullable=True, index=True)
    _parent_hash = Column(
        LargeBinary(32), ForeignKey("header.hash"), nullable=True, index=True
    )
    uncles_hash = Column(LargeBinary(32), nullable=False)
    coinbase = Column(LargeBinary(20), nullable=False)
    state_root = Column(LargeBinary(32), nullable=False)
    transaction_root = Column(LargeBinary(32), nullable=False)
    receipt_root = Column(LargeBinary(32), nullable=False)
    _bloom = Column(LargeBinary(1024), nullable=False)
    difficulty = Column(LargeBinary(32), nullable=False)
    block_number = Column(BigInteger, index=True, nullable=False)
    gas_limit = Column(BigInteger, nullable=False)
    gas_used = Column(BigInteger, nullable=False)
    timestamp = Column(Integer, nullable=False)
    extra_data = Column(LargeBinary, nullable=False)
    # mix_hash = Column(LargeBinary(32), nullable=False)
    nonce = Column(LargeBinary(8), nullable=False)

    children = relationship(
        "Header", backref=backref("parent", remote_side=[hash])  # type: ignore
    )

    def __repr__(self) -> str:
        return (
            f"Header("
            f"is_canonical={self.is_canonical!r}, "
            f"hash={self.hash!r}, "
            f"_detatched_parent_hash={self._detatched_parent_hash!r}, "
            f"_parent_hash={self._parent_hash!r}, "
            f"uncles_hash={self.uncles_hash!r}, "
            f"coinbase={self.coinbase!r}, "
            f"state_root={self.state_root!r}, "
            f"transaction_root={self.transaction_root!r}, "
            f"receipt_root={self.receipt_root!r}, "
            f"_bloom={self._bloom!r}, "
            f"difficulty={self.difficulty!r}, "
            f"block_number={self.block_number!r}, "
            f"gas_limit={self.gas_limit!r}, "
            f"gas_used={self.gas_used!r}, "
            f"timestamp={self.timestamp!r}, "
            f"extra_data={self.extra_data!r}, "
            f"nonce={self.nonce!r}, "
            ")"
        )

    def __str__(self) -> str:
        return (
            f"Header[#{self.block_number} {humanize_hash(self.hash)}]"  # type: ignore
        )

    @property
    def is_genesis(self) -> bool:
        return (
            self.block_number == 0
            and self.is_canonical  # noqa: W503
            and self.parent_hash == GENESIS_PARENT_HASH  # noqa: W503
        )

    @property
    def is_detatched(self) -> bool:
        return self._parent_hash is None and self._detatched_parent_hash is not None

    @property
    def parent_hash(self) -> Optional[Hash32]:
        if self._parent_hash is not None and self._detatched_parent_hash is not None:
            raise TypeError("Invalid: header has two parent hashes")
        elif self._detatched_parent_hash is not None:
            return Hash32(self._detatched_parent_hash)
        elif self._parent_hash is None:
            if self.block_number == 0:
                return GENESIS_PARENT_HASH
            else:
                return None
        else:
            return Hash32(self._parent_hash)

    @parent_hash.setter
    def parent_hash(self, value: Optional[Hash32]) -> None:
        if value == GENESIS_PARENT_HASH and self.block_number == 0:
            self._parent_hash = None
        else:
            self._parent_hash = value


class BlockTransaction(Base):
    query = Session.query_property()

    __tablename__ = "blocktransaction"
    __table_args__ = (
        Index(
            "ix_blocktransaction_idx_block_header_hash",
            "idx",
            "block_header_hash",
            unique=True,
        ),
        Index(
            "ix_block_header_hash_transaction_hash",
            "block_header_hash",
            "transaction_hash",
            unique=True,
        ),
        CheckConstraint("idx >= 0", name="_idx_positive"),
    )
    idx = Column(Integer, nullable=False)

    block_header_hash = Column(
        LargeBinary(32), ForeignKey("block.header_hash"), primary_key=True
    )
    transaction_hash = Column(
        LargeBinary(32), ForeignKey("transaction.hash"), primary_key=True
    )

    block = relationship("Block", back_populates="blocktransactions")
    transaction = relationship("Transaction", back_populates="blocktransactions")
    receipt = relationship(
        "Receipt",
        back_populates="blocktransaction",
        foreign_keys="(Receipt.transaction_hash, Receipt.block_header_hash)",
    )


class Block(Base):
    query = Session.query_property()

    __tablename__ = "block"

    header_hash = Column(LargeBinary(32), ForeignKey("header.hash"), primary_key=True)
    header = relationship("Header", back_populates="block")

    uncles = relationship("Header", secondary="blockuncle", order_by=BlockUncle.idx)
    transactions = relationship(
        "Transaction", secondary="blocktransaction", order_by=BlockTransaction.idx
    )

    blocktransactions = relationship("BlockTransaction")
    receipts = relationship(
        "Receipt",
        secondary="blocktransaction",
        order_by=BlockTransaction.idx,
        foreign_keys="(Receipt.transaction_hash, Receipt.block_header_hash)",
        primaryjoin=(
            "and_("
            "Receipt.transaction_hash == BlockTransaction.transaction_hash, "
            "Receipt.block_header_hash == BlockTransaction.block_header_hash, "
            "BlockTransaction.block_header_hash == Block.header_hash, "
            ")"
        ),
    )


class Transaction(Base):
    query = Session.query_property()

    __tablename__ = "transaction"
    __table_args__ = (
        CheckConstraint("gas >= 0", name="_gas_positive"),
        CheckConstraint("gas_price >= 0", name="_gas_price_positive"),
        CheckConstraint("nonce >= 0", name="_nonce_positive"),
    )

    hash = Column(LargeBinary(32), primary_key=True)

    block_header_hash = Column(
        LargeBinary(32), ForeignKey("block.header_hash"), nullable=True, index=True
    )
    block = relationship("Block")

    blocks = relationship(
        "Block", secondary="blocktransaction", order_by=BlockTransaction.idx
    )
    blocktransactions = relationship("BlockTransaction", back_populates="transaction")

    canonical_receipt = relationship(
        "Receipt",
        uselist=False,
        secondary="blocktransaction",
        back_populates="transaction",
        foreign_keys="(Receipt.transaction_hash, Receipt.block_header_hash)",
        primaryjoin=(
            "and_("
            "Receipt.transaction_hash == BlockTransaction.transaction_hash, "
            "Receipt.block_header_hash == BlockTransaction.block_header_hash, "
            "BlockTransaction.transaction_hash == Transaction.hash, "
            "BlockTransaction.block_header_hash == Transaction.block_header_hash, "
            ")"
        ),
    )
    receipts = relationship(
        "Receipt",
        secondary="blocktransaction",
        back_populates="transaction",
        foreign_keys="Receipt.transaction_hash",
        primaryjoin=(
            "and_("
            "Receipt.transaction_hash == BlockTransaction.transaction_hash, "
            "BlockTransaction.transaction_hash == Transaction.hash, "
            ")"
        ),
    )

    nonce = Column(BigInteger, nullable=False)
    gas_price = Column(BigInteger, nullable=False)
    gas = Column(BigInteger, nullable=False)
    to = Column(LargeBinary(20), nullable=True)
    value = Column(LargeBinary(32), nullable=False)
    data = Column(LargeBinary, nullable=False)
    v = Column(LargeBinary(32), nullable=False)
    r = Column(LargeBinary(32), nullable=False)
    s = Column(LargeBinary(32), nullable=False)

    sender = Column(LargeBinary(20), nullable=False)


class Receipt(Base):
    query = Session.query_property()

    __tablename__ = "receipt"
    __table_args__ = (
        ForeignKeyConstraint(
            ("transaction_hash", "block_header_hash"),
            ("blocktransaction.transaction_hash", "blocktransaction.block_header_hash"),
        ),
        UniqueConstraint(
            "transaction_hash",
            "block_header_hash",
            name="uix_transaction_hash_block_header_hash",
        ),
        CheckConstraint("gas_used >= 0", name="_gas_used_positive"),
    )
    __mapper_args__ = {"confirm_deleted_rows": False}

    block_header_hash = Column(
        LargeBinary(32),
        ForeignKey("blocktransaction.block_header_hash"),
        primary_key=True,
        index=True,
    )
    transaction_hash = Column(
        LargeBinary(32),
        ForeignKey("blocktransaction.transaction_hash"),
        primary_key=True,
        index=True,
    )
    blocktransaction = relationship(
        "BlockTransaction",
        back_populates="receipt",
        foreign_keys=(transaction_hash, block_header_hash),
    )

    transaction = relationship(
        "Transaction",
        uselist=False,
        secondary="blocktransaction",
        back_populates="receipts",
        primaryjoin=and_(
            Transaction.hash == BlockTransaction.transaction_hash,
            BlockTransaction.transaction_hash == transaction_hash,
            BlockTransaction.block_header_hash == block_header_hash,
        ),
    )
    logs = relationship(
        "Log",
        foreign_keys="(Log.transaction_hash, Log.block_header_hash)",
        order_by="Log.idx",
    )

    state_root = Column(LargeBinary(32), nullable=False)
    gas_used = Column(BigInteger, nullable=False)
    _bloom = Column(LargeBinary(1024), nullable=False)

    @property
    def bloom(self) -> int:
        return big_endian_to_int(self._bloom)

    @bloom.setter
    def bloom(self, value: int) -> None:
        self._bloom = int_to_big_endian(value)

    def __repr__(self) -> str:
        return (
            f"Receipt("
            f"block_header_hash={self.block_header_hash!r}, "
            f"transaction_hash={self.transaction_hash!r}, "
            f"state_root={self.state_root!r}, "
            f"gas_used={self.gas_used!r}, "
            f"bloom={self._bloom!r}"
            ")"
        )

    def __str__(self) -> str:
        return (
            f"Receipt("  # type: ignore
            f"txn_hash={humanize_hash(self.transaction_hash)}, "
            f"state_root={humanize_hash(self.state_root)}, "
            f"gas_used={self.gas_used}, "
            f"bloom={humanize_hash(self._bloom)}, "
            ")"
        )


class LogTopic(Base):
    query = Session.query_property()

    __tablename__ = "logtopic"
    __table_args__ = (
        UniqueConstraint(
            "idx",
            "log_idx",
            "log_transaction_hash",
            "log_block_header_hash",
            name="ix_idx_log_idx_log_transaction_hash_log_block_header_hash",
        ),
        Index(
            "ix_idx_topic_topic_log_idx_log_transaction_hash_log_block_header_hash",
            "idx",
            "topic_topic",
            "log_idx",
            "log_transaction_hash",
            "log_block_header_hash",
        ),
        ForeignKeyConstraint(
            ("log_idx", "log_transaction_hash", "log_block_header_hash"),
            ("log.idx", "log.transaction_hash", "log.block_header_hash"),
        ),
        CheckConstraint("idx >= 0 AND idx <= 3", name="_limit_4_topics_per_log"),
    )
    __mapper_args__ = {"confirm_deleted_rows": False}

    idx = Column(Integer, nullable=False, primary_key=True)

    topic_topic = Column(
        LargeBinary(32), ForeignKey("topic.topic"), index=True, nullable=False
    )
    log_idx = Column(Integer, nullable=False, primary_key=True)
    log_transaction_hash = Column(
        LargeBinary(32), nullable=False, index=True, primary_key=True
    )
    log_block_header_hash = Column(
        LargeBinary(32), nullable=False, index=True, primary_key=True
    )

    topic = relationship("Topic")
    log = relationship(
        "Log", foreign_keys=[log_idx, log_transaction_hash, log_block_header_hash]
    )


class Log(Base):
    query = Session.query_property()

    __tablename__ = "log"
    __table_args__ = (
        UniqueConstraint(
            "idx",
            "transaction_hash",
            "block_header_hash",
            name="uix_idx_transaction_hash_block_header_hash",
        ),
        ForeignKeyConstraint(
            ("transaction_hash", "block_header_hash"),
            ("receipt.transaction_hash", "receipt.block_header_hash"),
        ),
        CheckConstraint("idx >= 0", name="_idx_positive"),
    )
    __mapper_args__ = {"confirm_deleted_rows": False}

    # composite primary key across `idx`, `transaction_hash`, and`block_header_hash`
    idx = Column(Integer, primary_key=True, index=True)
    transaction_hash = Column(
        LargeBinary(32),
        ForeignKey("receipt.transaction_hash"),
        primary_key=True,
        index=True,
    )
    block_header_hash = Column(
        LargeBinary(32),
        ForeignKey("receipt.block_header_hash"),
        primary_key=True,
        index=True,
    )

    receipt = relationship(
        "Receipt",
        back_populates="logs",
        foreign_keys=(transaction_hash, block_header_hash),
    )

    address = Column(LargeBinary(20), index=True, nullable=False)
    topics = relationship(
        "Topic",
        secondary="logtopic",
        order_by=LogTopic.idx,
        primaryjoin=and_(
            LogTopic.log_idx == idx,
            LogTopic.log_transaction_hash == transaction_hash,
            LogTopic.log_block_header_hash == block_header_hash,
        ),
    )
    logtopics = relationship(
        "LogTopic",
        foreign_keys=(
            LogTopic.log_idx,
            LogTopic.log_transaction_hash,
            LogTopic.log_block_header_hash,
        ),
        cascade="all",
    )
    data = Column(LargeBinary, nullable=False)

    def __repr__(self) -> str:
        return (
            f"Log("
            f"idx={self.idx!r}, "
            f"block_header_hash={self.block_header_hash!r}, "
            f"transaction_hash={self.transaction_hash!r}, "
            f"address={self.address!r}, "
            f"data={self.data!r}, "
            f"topics={self.topics!r}"
            f")"
        )

    def __str__(self) -> str:
        # TODO: use eth_utils.humanize_bytes once it is released
        if len(self.data) > 4:
            pretty_data = humanize_hash(Hash32(self.data))
        else:
            pretty_data = self.data.hex()

        if len(self.topics) == 0:  # type: ignore
            pretty_topics = "(anonymous)"
        else:
            pretty_topics = "|".join(
                (
                    humanize_hash(Hash32(topic.topic))
                    for topic in self.topics  # type: ignore
                )
            )

        return (
            f"Log[#{self.idx} "  # type: ignore
            f"addr={humanize_hash(self.address)} "
            f"data={pretty_data} "
            f"topics={pretty_topics}"
            "]"
        )


class Topic(Base):
    query = Session.query_property()

    __tablename__ = "topic"

    topic = Column(LargeBinary(32), primary_key=True)

    logs = relationship(
        "Log",
        secondary="logtopic",
        primaryjoin=(LogTopic.topic_topic == topic),
        secondaryjoin=and_(
            LogTopic.log_idx == Log.idx,
            LogTopic.log_transaction_hash == Log.transaction_hash,
            LogTopic.log_block_header_hash == Log.block_header_hash,
        ),
    )

    def __repr__(self) -> str:
        return f"Topic(topic={self.topic!r})"

    def __str__(self) -> str:
        return f"Topic[{humanize_hash(self.topic)}]"  # type: ignore
