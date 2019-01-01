using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        internal const int crypto_kx_PUBLICKEYBYTES = 32;
        internal const int crypto_kx_SECRETKEYBYTES = 32;
        internal const int crypto_kx_SEEDBYTES = 32;
        internal const int crypto_kx_SESSIONKEYBYTES = 32;

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int crypto_kx_client_session_keys(
            byte* rx,
            byte* tx,
            PublicKeyBytes* client_pk,
            byte* client_sk,
            PublicKeyBytes* server_pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int crypto_kx_server_session_keys(
            byte* rx,
            byte* tx,
            PublicKeyBytes* server_pk,
            byte* server_sk,
            PublicKeyBytes* client_pk);

        [DllImport(Libraries.Libsodium, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int crypto_kx_seed_keypair(
            PublicKeyBytes* pk,
            byte* sk,
            byte* seed);
    }
}
