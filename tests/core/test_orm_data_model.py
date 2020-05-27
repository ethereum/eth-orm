from eth_orm.constants import GENESIS_PARENT_HASH
from eth_orm.models import Block, Header, Receipt, Topic, Transaction
from eth_orm.tools.factories import (
    BlockFactory,
    BlockTransactionFactory,
    BlockUncleFactory,
    HeaderFactory,
    LogFactory,
    LogTopicFactory,
    ReceiptFactory,
    TopicFactory,
    TransactionFactory,
)


def test_orm_single_topic(session):
    topic = TopicFactory()

    with session.begin_nested():
        session.add(topic)

    topic_from_db = session.query(Topic).filter(Topic.topic == topic.topic).one()

    assert topic_from_db.topic == topic.topic


def test_orm_log_without_topics(session):
    log = LogFactory()

    with session.begin_nested():
        session.add(log)

    session.refresh(log)
    assert len(log.topics) == 0


def test_orm_log_with_single_topic(session):
    topic = TopicFactory()
    log = LogFactory()
    log_topic = LogTopicFactory(log=log, topic=topic, idx=0)

    with session.begin_nested():
        session.add_all((log, topic, log_topic))

    session.refresh(log)

    assert len(log.topics) == 1
    assert log.topics[0] == topic


def test_orm_log_with_multiple_topics(session):
    topic_a, topic_b, topic_c = TopicFactory.create_batch(3)
    log = LogFactory()
    log_topic_0 = LogTopicFactory(topic=topic_b, log=log, idx=0)
    log_topic_1 = LogTopicFactory(topic=topic_a, log=log, idx=1)
    log_topic_2 = LogTopicFactory(topic=topic_c, log=log, idx=2)

    with session.begin_nested():
        session.add_all(
            (log, topic_a, topic_b, topic_c, log_topic_0, log_topic_1, log_topic_2)
        )

    session.refresh(log)

    assert len(log.topics) == 3
    assert log.topics[0].topic == topic_b.topic
    assert log.topics[1].topic == topic_a.topic
    assert log.topics[2].topic == topic_c.topic


def test_orm_receipt_without_logs(session):
    receipt = ReceiptFactory()

    with session.begin_nested():
        session.add(receipt)

    receipt_from_db = (
        session.query(Receipt)
        .filter(Receipt.transaction_hash == receipt.transaction_hash)
        .one()
    )

    assert receipt_from_db.transaction_hash == receipt.transaction_hash
    assert len(receipt.logs) == 0
    assert receipt_from_db.transaction.hash == receipt.transaction_hash


def test_orm_receipt_with_single_log(session):
    receipt = ReceiptFactory()
    log = LogFactory(receipt=receipt, idx=0)

    with session.begin_nested():
        session.add_all((log, receipt))

    session.refresh(receipt)

    assert len(receipt.logs) == 1
    assert receipt.logs[0] == log


def test_orm_receipt_with_multiple_logs(session):
    receipt = ReceiptFactory()
    log_b = LogFactory(receipt=receipt, idx=1)
    log_a = LogFactory(receipt=receipt, idx=0)
    log_c = LogFactory(receipt=receipt, idx=2)

    with session.begin_nested():
        session.add_all((log_b, log_a, log_c, receipt))

    session.refresh(receipt)

    assert len(receipt.logs) == 3
    assert receipt.logs[0] == log_a
    assert receipt.logs[1] == log_b
    assert receipt.logs[2] == log_c


def test_orm_simple_transaction(session):
    transaction = TransactionFactory()

    with session.begin_nested():
        session.add(transaction)

    transaction_from_db = (
        session.query(Transaction).filter(Transaction.hash == transaction.hash).one()
    )
    assert transaction_from_db.hash == transaction.hash


def test_orm_transaction_without_block(session):
    transaction = TransactionFactory(block=None)

    with session.begin_nested():
        session.add(transaction)

    transaction_from_db = (
        session.query(Transaction).filter(Transaction.hash == transaction.hash).one()
    )
    assert transaction_from_db.hash == transaction.hash
    assert transaction.block is None
    assert len(transaction.blocks) == 0


def test_orm_transaction_with_non_canonical_block(session):
    block = BlockFactory(header__is_canonical=False)
    transaction = TransactionFactory(block=None)
    block_transaction = BlockTransactionFactory(
        block=block, transaction=transaction, idx=0
    )

    with session.begin_nested():
        session.add_all((block, transaction, block_transaction))

    transaction_from_db = (
        session.query(Transaction).filter(Transaction.hash == transaction.hash).one()
    )
    assert transaction_from_db.hash == transaction.hash
    assert transaction.block is None
    assert len(transaction.blocks) == 1
    assert transaction.blocks[0].header_hash == block.header_hash


def test_orm_simple_block(session):
    block = BlockFactory()

    with session.begin_nested():
        session.add(block)

    block_from_db = (
        session.query(Block).filter(Block.header_hash == block.header_hash).one()
    )

    assert block_from_db.header_hash == block.header_hash
    assert len(block.transactions) == 0


def test_orm_block_transaction_ordering(session):
    block = BlockFactory()

    transaction_b = TransactionFactory(block=block)
    transaction_a = TransactionFactory(block=block)
    transaction_c = TransactionFactory(block=block)

    block_transaction_b = BlockTransactionFactory(
        block=block, transaction=transaction_b, idx=1
    )
    block_transaction_a = BlockTransactionFactory(
        block=block, transaction=transaction_a, idx=0
    )
    block_transaction_c = BlockTransactionFactory(
        block=block, transaction=transaction_c, idx=2
    )

    with session.begin_nested():
        session.add_all(
            (
                block,
                transaction_a,
                transaction_b,
                transaction_c,
                block_transaction_a,
                block_transaction_b,
                block_transaction_c,
            )
        )

    block_from_db = (
        session.query(Block).filter(Block.header_hash == block.header_hash).one()
    )

    assert len(block_from_db.transactions) == 3
    assert block_from_db.transactions[0].hash == transaction_a.hash
    assert block_from_db.transactions[1].hash == transaction_b.hash
    assert block_from_db.transactions[2].hash == transaction_c.hash


def test_orm_block_with_uncles(session):
    block = BlockFactory()

    uncle_b = HeaderFactory()
    uncle_a = HeaderFactory()
    uncle_c = HeaderFactory()

    block_uncle_b = BlockUncleFactory(block=block, uncle=uncle_b, idx=1)
    block_uncle_a = BlockUncleFactory(block=block, uncle=uncle_a, idx=0)
    block_uncle_c = BlockUncleFactory(block=block, uncle=uncle_c, idx=2)

    with session.begin_nested():
        session.add_all(
            (
                block,
                uncle_a,
                uncle_b,
                uncle_c,
                block_uncle_a,
                block_uncle_b,
                block_uncle_c,
            )
        )

    block_from_db = (
        session.query(Block).filter(Block.header_hash == block.header_hash).one()
    )

    assert len(block_from_db.uncles) == 3
    assert block_from_db.uncles[0].hash == uncle_a.hash
    assert block_from_db.uncles[1].hash == uncle_b.hash
    assert block_from_db.uncles[2].hash == uncle_c.hash


def test_orm_simple_header(session):
    header = HeaderFactory()

    with session.begin_nested():
        session.add(header)

    header_from_db = session.query(Header).filter(Header.hash == header.hash).one()

    assert header_from_db.hash == header.hash


def test_orm_genesis_header(session):
    header = HeaderFactory(_parent_hash=None)

    with session.begin_nested():
        session.add(header)

    header_from_db = session.query(Header).filter(Header.hash == header.hash).one()

    assert header_from_db.hash == header.hash
    assert header_from_db.parent_hash == GENESIS_PARENT_HASH
