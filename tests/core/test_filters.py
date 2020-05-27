from eth_orm.tools.factories import AddressFactory, Hash32Factory
from eth_orm.tools.filter import FilterParams, filter_logs
from eth_orm.tools.logs import check_filter_results, construct_log


def test_filter_log_empty_params(session):
    log = construct_log(session)

    params = FilterParams()

    results = filter_logs(session, params)

    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log


def test_filter_log_single_address_match(session):
    address = AddressFactory()
    log = construct_log(session, address=address)

    params = FilterParams(address=address)

    results = filter_logs(session, params)

    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log


def test_filter_log_multiple_addresses(session):
    address = AddressFactory()
    other = AddressFactory()

    log = construct_log(session, address=address)
    construct_log(session)  # another log that doesn't match

    params = FilterParams(address=(other, address))

    results = filter_logs(session, params)

    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log


def test_filter_log_before_from_block(session):
    construct_log(session, block_number=0)

    params = FilterParams(from_block=1)

    results = filter_logs(session, params)
    assert not results


def test_filter_log_after_to_block(session):
    construct_log(session, block_number=2)

    params = FilterParams(to_block=1)

    results = filter_logs(session, params)
    assert not results


def test_filter_log_after_from_block_null_to_block(session):
    log = construct_log(session, block_number=2)
    construct_log(session, block_number=0)  # another log that doesn't match

    params = FilterParams(from_block=1)

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log


def test_filter_log_null_from_block_before_to_block(session):
    log = construct_log(session, block_number=2)
    construct_log(session, block_number=6)  # another log that doesn't match

    params = FilterParams(to_block=5)

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log


def test_filter_log_single_topic(session):
    topic = Hash32Factory()
    log = construct_log(session, topics=(topic,))
    construct_log(session)  # another log that doesn't match
    assert log.topics[0].topic == topic

    params = FilterParams(topics=(topic,))

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log
    assert results[0].topics[0].topic == topic


def test_filter_log_multiple_topics(session):
    topic_0 = Hash32Factory()
    topic_1 = Hash32Factory()
    log = construct_log(session, topics=(topic_0, topic_1))
    construct_log(session)  # another log that doesn't match

    params = FilterParams(topics=(topic_0, topic_1))

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log
    assert results[0].topics[0].topic == topic_0
    assert results[0].topics[1].topic == topic_1


def test_filter_log_single_topic_out_of_position(session):
    topic = Hash32Factory()
    wrong_topic = Hash32Factory()
    construct_log(session, topics=(wrong_topic, topic))

    params = FilterParams(topics=(topic,))

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 0


def test_filter_log_single_topic_second_position(session):
    topic = Hash32Factory()
    log = construct_log(session, topics=(Hash32Factory(), topic))
    construct_log(session)  # another log that doesn't match

    params = FilterParams(topics=(None, topic))

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 1
    assert results[0] == log
    assert results[0].topics[1].topic == topic


def test_filter_params_with_multiple_options_for_topic(session):
    topic_a = Hash32Factory()
    topic_b = Hash32Factory()
    log_a = construct_log(session, topics=(topic_a,))
    log_b = construct_log(session, topics=(topic_b,))
    construct_log(session)  # another log that doesn't match

    params = FilterParams(topics=((topic_a, topic_b),))

    results = filter_logs(session, params)
    check_filter_results(params, results)

    assert len(results) == 2
    assert results[0] in {log_a, log_b}
    assert results[1] in {log_a, log_b}

    assert results[0].topics[0].topic in {topic_a, topic_b}
    assert results[1].topics[0].topic in {topic_a, topic_b}
