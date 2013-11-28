"""Client for the Bitmymoney PSP REST API

Library to integrate the Bitmymoney Bitcoin payment service provider into
Python web applications.
"""

BASE_URL = 'http://localhost:8000/secure/pay'

import hmac
import hashlib
import decimal
import json
import re

import requests


class ServerError(Exception):
    """Raised on server errors
    """
    def __init__(self, code, message, body):
        self.code = code
        self.body = body
        super(ServerError, self).__init__(message)


class InvalidSignature(Exception):
    """Raised if a signature is not correct
    """


class PSPClient(object):
    """Client library for the Bitmymoney PSP REST API
    """
    def __init__(self, apikey, base_url=BASE_URL):
        self.apikey = apikey
        if base_url.endswith('/'):
            base_url = base_url[:-1]
        self.base_url = base_url

    def start(
            self, amount_eur, description, url_success, callback_success,
            merchant_id, order_id=None, url_failure=None,
            callback_failure=None, nonce=None):
        """Initiate the payment procedure

        This prepares a session on the system for this payment, and returns
        information about where to redirect the client to, the bitcoin address
        used, etc.

        Return value is a structure with keys 'url_pay', 'btc_address',
        'url_qrcode', 'url_status' and 'sign'. The sign is verified
        automatically.

        The client must be redirected to 'url_pay' to continue the payment
        process. Once the transaction is finished, 'callback_success' or
        'callback_failure' are called by the system to notify the merchant
        website (you) of transaction status changes. When the client is done,
        (s)he is redirected to 'url_success' or 'url_failure', depending on
        payment status.
        """
        amount_eur = self._normalize_amount(amount_eur)
        sign_fields = (
            'amount_eur', 'description', 'url_success', 'merchant_id')
        data = self._call(
            '/start/', amount_eur=amount_eur, description=description,
            url_success=url_success, callback_success=callback_success,
            merchant_id=merchant_id, order_id=order_id,
            url_failure=url_failure, callback_failure=callback_failure,
            nonce=nonce, sign_fields=sign_fields)
        self._verify_signature(
            data, ('url_pay', 'btc_address', 'url_qrcode', 'url_status'))
        return data

    def price_btc(self, amount_eur, decimals=5):
        """Returns the price in Bitcoins for an amount of Euro
        """
        amount_eur = self._normalize_amount(amount_eur)
        if decimals < 0:
            raise ValueError('decimals must be a positive integer')
        return decimal.Decimal(self._call(
            '/price_btc/', amount_eur=amount_eur, decimals=decimals))

    def transaction_status(self, txid, nonce=None):
        """Returns transaction information
        """
        data = self._call('/tx/%s/status/' % (txid,))
        sigdata = data.copy()
        sigdata['nonce'] = nonce
        self._verify_signature(
            data, ('status', 'amount_btc', 'amount_received', 'txid'))
        return {
            'status': data['status'],
            'amount_btc': decimal.Decimal(data['amount_btc']),
            'amount_received': decimal.Decimal(data['amount_received']),
            'txid': data['txid'],
            'sign': data['sign'],
        }

    def _call(self, path, method='GET', sign_fields=(), **kwargs):
        data = kwargs.copy()
        if sign_fields:
            signvalues = []
            for field in sign_fields:
                signvalues.append(str(data[field]))
            signvalues.append(data.pop('nonce', '') or '')
            sign = hmac.new(
                self.apikey, ''.join(signvalues), hashlib.sha256).hexdigest()
            data['sign'] = sign
        reqfunc = getattr(requests, method.lower())
        response = reqfunc('%s%s' % (self.base_url, path), params=data)
        if response.status_code < 200 or response.status_code >= 400:
            raise ServerError(
                response.status_code, response.reason, response.text)
        return response.json()

    def _verify_signature(self, data, fields):
        signvalues = []
        for field in fields:
            signvalues.append(str(data[field]))
        signvalues.append(data.get('nonce', ''))
        sign = hmac.new(
            self.apikey, ''.join(signvalues), hashlib.sha256).hexdigest()
        if sign != data['sign']:
            raise InvalidSignature(data['sign'])

    _reg_decimal = re.compile('^\d+([.]\d+)?$')
    def _normalize_amount(self, amount):
        amount = str(amount)
        if not self._reg_decimal.match(amount):
            raise ValueError(
                'could not parse amount %r, must be a positive decimal' % (
                    amount,))
        return amount
