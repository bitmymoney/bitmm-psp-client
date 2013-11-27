import unittest
import json
import hmac
import hashlib
import httplib
import decimal

import requests

from bitmm.psp import client

def sign(data, fields, apikey):
    values = []
    for field in fields:
        values.append(str(data[field]))
    return hmac.new(''.join(values), apikey, hashlib.sha256).hexdigest()


class ClientTestCase(unittest.TestCase):
    def setUp(self):
        self._org_get = requests.get
        self._org_post = requests.post
        requests.get = self._mocked_get_post
        requests.post = self._mocked_get_post

        self.apikey = '1234567890'
        self.responses = []
        self.response_tests = []

        self.client = client.PSPClient(self.apikey)

    def tearDown(self):
        requests.get = self._org_get
        requests.post = self._org_post

    def test_start(self):
        data = {
            'url_pay': 'http://test.bitmymoney.com/tx/1234/',
            'btc_address': '123456',
            'url_qrcode': 'http://test.bitmymoney.com/tx/1234/qrcode.png',
            'url_status': 'http://test.bitmymoney.com/tx/1234/status',
        }
        data['sign'] = sign(
            data, ('url_pay', 'btc_address', 'url_qrcode', 'url_status'),
            self.apikey)

        self.responses = [
            (200, json.dumps(data)),
        ]

        retdata = self.client.start(
            '10.00', 'Test', 'http://example.com/thankyou',
            'http://example.com/success_callback', 1)
        self.assertEquals(retdata, data)

    def test_start_invalid_signature(self):
        data = {
            'url_pay': 'http://test.bitmymoney.com/tx/1234/',
            'btc_address': '123456',
            'url_qrcode': 'http://test.bitmymoney.com/tx/1234/qrcode.png',
            'url_status': 'http://test.bitmymoney.com/tx/1234/status',
        }
        data['sign'] = sign(
            data, ('url_pay', 'btc_address', 'url_qrcode', 'url_status'),
            self.apikey)
        # meddle with the data to make the signature invalid
        data['btc_address'] = '123457'

        self.responses = [
            (200, json.dumps(data)),
        ]

        self.assertRaises(
            client.InvalidSignature,
            self.client.start,
            '10.00', 'Test', 'http://example.com/thankyou',
            'http://example.com/success_callback', 1)

    def test_transaction_status(self):
        data = {
            'status': 'SUCCESS',
            'amount_btc': '0.1',
            'amount_received': '0.1',
            'txid': '123456',
        }
        data['sign'] = sign(
            data, ('status', 'amount_btc', 'amount_received', 'txid'),
            self.apikey)
        self.responses = [
            (200, json.dumps(data)),
        ]

        retdata = self.client.transaction_status('123456')
        self.assertEquals(retdata.keys(), data.keys())
        self.assertEquals(
            retdata['amount_btc'], decimal.Decimal(data['amount_btc']))

    def test_price_btc(self):
        self.responses = [(200, '"1.10000"')]
        ret = self.client.price_btc('500')
        self.assertEquals(ret, decimal.Decimal('1.10000'))

        self.responses = [(200, '"1.10000"')]
        ret = self.client.price_btc('500.1')
        self.assertEquals(ret, decimal.Decimal('1.10000'))

        self.assertRaises(ValueError, self.client.price_btc, '-1.0')
        self.assertRaises(ValueError, self.client.price_btc, '1,0')

    def _mocked_get_post(self, *args, **kwargs):
        if self.response_tests:
            test = self.response_tests.pop(0)
            test(*args, **kwargs)
        resdata = self.responses.pop(0)
        res = requests.Response()
        res.status_code = resdata[0]
        res.reason = httplib.responses[resdata[0]]
        res._content = resdata[1]
        return res


if __name__ == '__main__':
    unittest.main()
