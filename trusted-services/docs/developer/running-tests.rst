Running Tests
=============



Running component tests
-----------------------
On successfully completing the steps above, a binary executable called 'component-test'
will have been created.  Because this deployment targets the linux-pc environment, the
executable may be run as a native application.  The application uses the stock CppUtest
command line test runner.

To run component tests, use::

  ./component-test -v

  Typical verbose output:
  TEST(PackedCprotocolChecks, checkTsStatusCodes) - 0 ms
  TEST(InternalTrustedStorageTests, storeNewItem) - 0 ms
  TEST(E2EcryptoOpTests, generateRandomNumbers) - 2 ms
  TEST(E2EcryptoOpTests, asymEncryptDecrypt) - 4 ms
  TEST(E2EcryptoOpTests, signAndVerifyHash) - 40 ms
  TEST(E2EcryptoOpTests, exportAndImportKeyPair) - 18 ms
  TEST(E2EcryptoOpTests, exportPublicKey) - 7 ms
  TEST(E2EcryptoOpTests, generatePersistentKeys) - 39 ms
  TEST(E2EcryptoOpTests, generateVolatileKeys) - 20 ms
  TEST(CryptoFaultTests, randomNumbersWithBrokenStorage) - 0 ms
  TEST(CryptoFaultTests, persistentKeysWithBrokenStorage) - 9 ms
  TEST(CryptoFaultTests, volatileKeyWithBrokenStorage) - 8 ms
  TEST(PocCryptoOpTests, checkOpSequence) - 13 ms
  TEST(CryptoMsgTests, SignHashOutMsgTest) - 0 ms
  TEST(CryptoMsgTests, SignHashInMsgTest) - 0 ms
  TEST(CryptoMsgTests, ExportPublicKeyOutMsgTest) - 1 ms
  TEST(CryptoMsgTests, ExportPublicKeyInMsgTest) - 0 ms
  TEST(CryptoMsgTests, GenerateKeyInMsgTest) - 0 ms
  TEST(ServiceFrameworkTests, serviceWithOps) - 0 ms
  TEST(ServiceFrameworkTests, serviceWithNoOps) - 0 ms
  TEST(TsDemoTests, runTsDemo) - 71 ms

  OK (21 tests, 21 ran, 159 checks, 0 ignored, 0 filtered out, 233 ms)



--------------

*Copyright (c) 2020-2021, Arm Limited and Contributors. All rights reserved.*

SPDX-License-Identifier: BSD-3-Clause
