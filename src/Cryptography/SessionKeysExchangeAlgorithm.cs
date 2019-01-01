using System;
using System.Buffers;
using System.Threading;
using NSec.Cryptography.Formatting;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    public sealed class SessionKeysExchangeAlgorithm : Algorithm
    {
        private static readonly PrivateKeyFormatter s_nsecPrivateKeyFormatter = new X25519PrivateKeyFormatter(new byte[] { 0xDE, 0x66, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, crypto_scalarmult_curve25519_BYTES, 0 });

        private static readonly PublicKeyFormatter s_nsecPublicKeyFormatter = new X25519PublicKeyFormatter(new byte[] { 0xDE, 0x67, 0x41, 0xDE, crypto_scalarmult_curve25519_SCALARBYTES, 0, crypto_scalarmult_curve25519_BYTES, 0 });

        private static readonly PrivateKeyFormatter s_pkixPrivateKeyFormatter = new X25519PrivateKeyFormatter(new byte[]
        {
            // +-- SEQUENCE (3 elements)
            //     +-- INTEGER 0
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- OCTET STRING (1 element)
            //         +-- OCTET STRING (32 bytes)
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
        });

        private static readonly PublicKeyFormatter s_pkixPublicKeyFormatter = new X25519PublicKeyFormatter(new byte[]
        {
            // +-- SEQUENCE (2 elements)
            //     +-- SEQUENCE (1 element)
            //     |   +-- OBJECT IDENTIFIER 1.3.101.110
            //     +-- BIT STRING (256 bits)
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65,
            0x6E, 0x03, 0x21, 0x00,
        });

        private static readonly PrivateKeyFormatter s_rawPrivateKeyFormatter = new X25519PrivateKeyFormatter(new byte[] { });

        private static readonly PublicKeyFormatter s_rawPublicKeyFormatter = new X25519PublicKeyFormatter(new byte[] { });

        private static SessionKeysExchangeAlgorithm s_kx;

        public static SessionKeysExchangeAlgorithm KX
        {
            get
            {
                SessionKeysExchangeAlgorithm instance = s_kx;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_kx, new SessionKeysExchangeAlgorithm(), null);
                    instance = s_kx;
                }
                return instance;
            }
        }

        internal override int GetKeySize() => crypto_kx_SECRETKEYBYTES;

        internal override int GetPublicKeySize() => crypto_kx_PUBLICKEYBYTES;

        internal override int GetSeedSize() => crypto_kx_SEEDBYTES;

        internal override unsafe void CreateKey(
            ReadOnlySpan<byte> seed,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);
            owner = memoryPool.Rent(crypto_kx_SECRETKEYBYTES);
            memory = owner.Memory.Slice(0, crypto_kx_SECRETKEYBYTES);

            fixed (PublicKeyBytes* pk = &publicKey.GetPinnableReference())
            fixed (byte* sk = owner.Memory.Span)
            fixed (byte* s = seed)
            {
                crypto_kx_seed_keypair(pk, sk, s);
            }
        }

        internal override bool TryExportKey(
            ReadOnlySpan<byte> key,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryExport(key, blob, out blobSize);
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryExportText(key, blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryExportPublicKey(
            PublicKey publicKey,
            KeyBlobFormat format,
            Span<byte> blob,
            out int blobSize)
        {
            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize);
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize);
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryExport(in publicKey.GetPinnableReference(), blob, out blobSize);
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryExportText(in publicKey.GetPinnableReference(), blob, out blobSize);
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            MemoryPool<byte> memoryPool,
            out ReadOnlyMemory<byte> memory,
            out IMemoryOwner<byte> owner,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);

            switch (format)
            {
            case KeyBlobFormat.RawPrivateKey:
                return s_rawPrivateKeyFormatter.TryImport(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            case KeyBlobFormat.NSecPrivateKey:
                return s_nsecPrivateKeyFormatter.TryImport(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPrivateKey:
                return s_pkixPrivateKeyFormatter.TryImport(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPrivateKeyText:
                return s_pkixPrivateKeyFormatter.TryImportText(blob, memoryPool, out memory, out owner, out publicKey.GetPinnableReference());
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        internal override bool TryImportPublicKey(
            ReadOnlySpan<byte> blob,
            KeyBlobFormat format,
            out PublicKey publicKey)
        {
            publicKey = new PublicKey(this);

            switch (format)
            {
            case KeyBlobFormat.RawPublicKey:
                return s_rawPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference());
            case KeyBlobFormat.NSecPublicKey:
                return s_nsecPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPublicKey:
                return s_pkixPublicKeyFormatter.TryImport(blob, out publicKey.GetPinnableReference());
            case KeyBlobFormat.PkixPublicKeyText:
                return s_pkixPublicKeyFormatter.TryImportText(blob, out publicKey.GetPinnableReference());
            default:
                throw Error.Argument_FormatNotSupported(nameof(format), format.ToString());
            }
        }

        public SessionKeyPair ExchangeClientSessionKeys(
            PublicKey clientPublicKey,
            Key clientPrivateKey,
            PublicKey serverPublicKey,
            in SharedSecretCreationParameters creationParameters = default)
        {
            return ExchangeSessionKeys(
                Role.Client,
                clientPublicKey,
                clientPrivateKey,
                serverPublicKey,
                creationParameters);
        }

        public SessionKeyPair ExchangeServerSessionKeys(
            PublicKey serverPublicKey,
            Key serverPrivateKey,
            PublicKey clientPublicKey,
            in SharedSecretCreationParameters creationParameters = default)
        {
            return ExchangeSessionKeys(
                Role.Server,
                serverPublicKey,
                serverPrivateKey,
                clientPublicKey,
                creationParameters);
        }

        internal unsafe SessionKeyPair ExchangeSessionKeys(
            Role role,
            PublicKey publicKey,
            Key privateKey,
            PublicKey otherPartyPublicKey,
            in SharedSecretCreationParameters creationParameters = default)
        {
            MemoryPool<byte> memoryPool = creationParameters.GetMemoryPool();

            IMemoryOwner<byte> rxMemoryOwner = memoryPool.Rent(crypto_kx_SESSIONKEYBYTES);
            Memory<byte> rxMemory = rxMemoryOwner.Memory.Slice(0, crypto_kx_SESSIONKEYBYTES);

            IMemoryOwner<byte> txMemoryOwner = memoryPool.Rent(crypto_kx_SESSIONKEYBYTES);
            Memory<byte> txMemory = txMemoryOwner.Memory.Slice(0, crypto_kx_SESSIONKEYBYTES);

            bool success = false;
            try
            {
                fixed (byte* rx = rxMemory.Span)
                fixed (byte* tx = txMemory.Span)
                fixed (PublicKeyBytes* pk = &publicKey.GetPinnableReference())
                fixed (byte* sk = privateKey.Span)
                fixed (PublicKeyBytes* otherPartyPk = &otherPartyPublicKey.GetPinnableReference())
                {
                    int error = role == Role.Server ?
                        crypto_kx_server_session_keys(rx, tx, pk, sk, otherPartyPk) :
                        crypto_kx_client_session_keys(rx, tx, pk, sk, otherPartyPk);

                    success = error == 0;

                    var rxKey = new SharedSecret(rxMemory, rxMemoryOwner);
                    var txKey = new SharedSecret(txMemory, txMemoryOwner);

                    return success ? new SessionKeyPair(rxKey, txKey) : null;
                }
            }
            finally
            {
                if (!success)
                {
                    rxMemoryOwner.Dispose();
                    txMemoryOwner.Dispose();
                }
            }
        }
    }

    public sealed class SessionKeyPair : IDisposable
    {
        internal SessionKeyPair(SharedSecret receiveKey, SharedSecret transmitKey)
        {
            ReceiveKey = receiveKey;
            TransmitKey= transmitKey;
        }

        public SharedSecret TransmitKey { get; }

        public SharedSecret ReceiveKey { get; }

        public void Dispose()
        {
            TransmitKey?.Dispose();
            ReceiveKey?.Dispose();
        }
    }

    internal enum Role
    {
        Client,
        Server
    }
}
