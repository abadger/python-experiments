import pwquality
import pytest

import ctypes_pwq
import cffi_api_gen_pwq


@pytest.fixture()
def baseline_pwqerror():
    yield pwquality.PWQError


@pytest.fixture()
def baseline_generate():
    pwq_ctx = pwquality.PWQSettings()
    yield pwq_ctx.generate


@pytest.fixture()
def baseline_check():
    pwq_ctx = pwquality.PWQSettings()
    yield pwq_ctx.check


@pytest.mark.parametrize('module', [ctypes_pwq, cffi_api_gen_pwq])
def test_generate(module, baseline_generate):
    ctx = module.PWQSettings()
    baseline = baseline_generate(1)
    module_password = ctx.generate(1)

    assert type(baseline) == type(module_password)
    # Assert that the length of the strings is close (hard to be exact because different alphabets
    # yield slightly more or less entrophy
    assert len(baseline) <= len(module_password) + 1
    assert len(baseline) >= len(module_password) - 1

    baseline = baseline_generate(107)
    module_password = ctx.generate(107)

    assert type(baseline) == type(module_password)
    assert len(baseline) <= len(module_password) + 1
    assert len(baseline) >= len(module_password) - 1


@pytest.mark.parametrize('module', [ctypes_pwq, cffi_api_gen_pwq])
@pytest.mark.parametrize('password', ['Thosdjkesd', 'Thosdjkesd%', 'Thosdjkesd%p~i l230-9'])
def test_check_succeed(module, baseline_check, password):
    ctx = module.PWQSettings()
    baseline = baseline_check(password)
    module_score = ctx.check(password)

    assert baseline == module_score


@pytest.mark.parametrize('module', [ctypes_pwq, cffi_api_gen_pwq])
@pytest.mark.parametrize('password', ['Thos', 'supercalifragilic', "pa's a s'ap"])
def test_check_fail(module, baseline_check, password):
    ctx = module.PWQSettings()
    with pytest.raises(pwquality.PWQError) as base_err:
        baseline = baseline_check(password)
    with pytest.raises(module.PWQError) as mod_err:
        module_score = ctx.check(password)

    assert base_err.value.args == mod_err.value.args
