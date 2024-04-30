from collections import namedtuple

AttackerFunctionTuple = namedtuple(
    'AttackerFunctionTuple',
    ['func', 'args', 'name', 'score', "service_check_func"]
)


def get_attack_config_list(attacker, sla_checker):
    config = [
        AttackerFunctionTuple(
            func=attacker.test_cmd_injection,
            args=(),
            name="Command Injection",
            score=7,
            service_check_func=sla_checker.check_cmd_injection,
        ),
        AttackerFunctionTuple(
            func=attacker.test_local_format_string_elliot,
            args=(),
            name="Local Format String",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),

        AttackerFunctionTuple(
            func=attacker.test_buffer_overflow,
            args=(),
            name="Buffer Overflow",
            score=7,
            service_check_func=sla_checker.check_buffer_overflow,
        ),

        AttackerFunctionTuple(
            func=attacker.test_ssh_elliot,
            args=(),
            name="ssh_elliot",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_mrrobot,
            args=(),
            name="ssh_mrrobot",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_trenton,
            args=(),
            name="ssh_trenton",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_darlene,
            args=(),
            name="ssh_darlene",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_trenton,
            args=(),
            name="ssh_mobley",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_ssh_trenton,
            args=(),
            name="ssh_leslie",
            score=3,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_backdoor_1,
            args=(),
            name="backdoor",
            score=5,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_backdoor_2,
            args=(),
            name="backdoor 2",
            score=5,
            service_check_func=sla_checker.dummy_check,
        ),
        AttackerFunctionTuple(
            func=attacker.test_lfi,
            args=(),
            name="lfi",
            score=7,
            service_check_func=sla_checker.check_lfi,
        ),
        AttackerFunctionTuple(
            func=attacker.test_reflected_xss,
            args=(),
            name="reflected xss",
            score=5,
            service_check_func=sla_checker.check_reflected_xss,
        ),
        AttackerFunctionTuple(
            func=attacker.test_arbitrary_file_upload,
            args=(),
            name="arbitrary file upload",
            score=5,
            service_check_func=sla_checker.check_arbitrary_file_upload,
        ),
        AttackerFunctionTuple(
            func=attacker.test_dom_based_xss,
            args=(),
            name="dom based xss",
            score=6,
            service_check_func=sla_checker.check_dom_based_xss,
        ),
        AttackerFunctionTuple(
            func=attacker.test_sqli,
            args=(),
            name="test sqli",
            score=12,
            service_check_func=sla_checker.check_sqli,
        ),
    ]
    return config
