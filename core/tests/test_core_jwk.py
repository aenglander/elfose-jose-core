import unittest

from elfose.jose.core.jwk import Key, KeyType, KeySet


class KeyKeyTypeTests(unittest.TestCase):
    def test_accepts_key_type_enum(self):
        self.assertIs(KeyType.EC, Key(KeyType.EC).kty)

    def test_denies_non_key_type_enum(self):
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            Key("")

    def test_key_type_required(self):
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            Key(None)


class KeyX5uTests(unittest.TestCase):
    def test_accepts_valid_uri(self):
        uri = "https://foo.bar/x5.cert"
        self.assertEqual(uri[:], Key(KeyType.EC, x5u=uri).x5u)

    def test_denies_uri_with_no_scheme(self):
        with self.assertRaises(ValueError):
            Key(KeyType.EC, x5u="//foo.bar/x5.cert")

    def test_denies_uri_with_no_network_location(self):
        with self.assertRaises(ValueError):
            Key(KeyType.EC, x5u="file:///x5.cert")

    def test_denies_non_str(self):
        with self.assertRaises(TypeError):
            # noinspection PyTypeChecker
            Key(KeyType.EC, x5u=False)


class KeySetTests(unittest.TestCase):

    def test_keys_is_set(self):
        key1 = Key(KeyType.EC)
        key2 = Key(KeyType.RSA)
        key_set = KeySet({key1, key2})
        self.assertEqual(len(key_set.keys), 2, "Length of keys was not two")
        self.assertIn(key1, key_set.keys, "Key 1 is missing")
        self.assertIn(key2, key_set.keys, "Key 2 is missing")

    def test_keys_is_immutable(self):
        key1 = Key(KeyType.EC)
        key2 = Key(KeyType.RSA)
        key_set = KeySet({key1, key2})
        key_set.keys.append(Key(KeyType.oct))
        
        self.assertEqual(len(key_set.keys), 2,
                         "Length of keys changed from append")
        key_set.keys.pop()
        self.assertEqual(len(key_set.keys), 2,
                         "Length of keys changed from pop")


if __name__ == '__main__':
    unittest.main()
