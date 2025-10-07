from unittest import mock

from presidio_anonymizer.operators.operator import OperatorType
import pytest

from presidio_anonymizer.operators import Encrypt, AESCipher
from presidio_anonymizer.entities import InvalidParamError


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_then_aes_encrypt_called_and_its_result_is_returned(
    mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text", params={"key": "key"})

    assert anonymized_text == expected_anonymized_text


@mock.patch.object(AESCipher, "encrypt")
def test_given_anonymize_with_bytes_key_then_aes_encrypt_result_is_returned(
        mock_encrypt,
):
    expected_anonymized_text = "encrypted_text"
    mock_encrypt.return_value = expected_anonymized_text

    anonymized_text = Encrypt().operate(text="text",
                                        params={"key": b'1111111111111111'})

    assert anonymized_text == expected_anonymized_text


def test_given_verifying_an_valid_length_key_no_exceptions_raised():
    Encrypt().validate(params={"key": "128bitslengthkey"})


def test_given_verifying_an_valid_length_bytes_key_no_exceptions_raised():
    Encrypt().validate(params={"key": b'1111111111111111'})

@pytest.mark.parametrize(
    "key, description",
    [
        ("6" * 16, "128-bit string key"),  
        ("6" * 24, "192-bit string key"),    
        ("6" * 32, "256-bit string key"),  
        (b'1' * 16, "128-bit bytes key"),  
        (b'1' * 24, "192-bit bytes key"),  
        (b'1' * 32, "256-bit bytes key"),  
    ],
)
def test_valid_keys(key, description):
    Encrypt().validate(params={"key": key})
def test_given_verifying_an_invalid_length_key_then_ipe_raised():
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": "key"})

@mock.patch.object(AESCipher, "is_valid_key_size")# hint: replace encrypt with the method that you want to mock
def test_given_verifying_an_invalid_length_bytes_key_then_ipe_raised(mock_is_valid_key_size): # hint: replace mock_encrypt with a proper name for your mocker
    #mock_aes_init.side_effect = ValueError("Invalid key length")
    mock_is_valid_key_size.return_value = False
    with pytest.raises(
        InvalidParamError,
        match="Invalid input, key must be of length 128, 192 or 256 bits",
    ):
        Encrypt().validate(params={"key": b'1111111111111111'})
def test_operator_name():
    encrypt_operator = Encrypt()
    assert encrypt_operator.operator_name() == "encrypt"
def test_operator_type():
    encrypt_operator = Encrypt()
    assert encrypt_operator.operator_type() == OperatorType.Anonymize