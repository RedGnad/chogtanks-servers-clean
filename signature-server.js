using System;
using System.Runtime.InteropServices;
using UnityEngine;

// BackendBridge : pont Unity <-> Serveur sécurisé (Firebase ID Token + appels protégés)
// WebGL uniquement pour les fonctions JS externes. En Editor/Standalone: stubs.
// Ajoute ce script à un GameObject (ex: _Backend) dans ta scène d'init.
// Séquence automatique: Start() -> Récupère token -> Test mint -> prêt.

public class BackendBridge : MonoBehaviour
{
#if UNITY_WEBGL && !UNITY_EDITOR
    [DllImport("__Internal")] static extern int GetFirebaseIdTokenJS(string go, string method, int forceRefresh);
    [DllImport("__Internal")] static extern int AuthorizedPostJS(string url, string bodyJson, string go, string method);
#endif

    [Header("Config Backend")] public string serverBase = "https://chogtanks-nft-servers.onrender.com"; // pas de slash final
    // Événement production: déclenché quand le token Firebase est prêt
    public event Action AuthReady;

    string _idToken;
    bool _tokenReady;
    float _nextTokenRenewAt;

    // Indicateur public (lecture seule) pour autres composants
    public bool IsAuthReady => _tokenReady;


    [Serializable] class MintReq { public string playerAddress; public int mintCost; }
    [Serializable] class UpdateReq { public string playerAddress; public string appKitWallet; public int scoreAmount; public int transactionAmount; }
    [Serializable] class GenericPostResult { public bool ok; public int status; public string body; public string error; }

    // NOTE: Pas de state joueur interne ici. Utiliser directement PlayerSession.WalletAddress.
    // Ex: backend.CallUpdatePlayer(PlayerSession.WalletAddress, PlayerSession.WalletAddress, score, txAmount);

    void Start()
    {
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.Log("[BackendBridge] Initialisation");
        #endif
        RequestToken();
        // Renewal passif toutes les 15 minutes
        InvokeRepeating(nameof(CheckTokenRenewal), 60f, 60f);
    }

    void CheckTokenRenewal()
    {
        if (_tokenReady && Time.realtimeSinceStartup > _nextTokenRenewAt - 120f) // 2 min marge
        {
            #if UNITY_EDITOR || DEVELOPMENT_BUILD
            Debug.Log("[BackendBridge] Renouvellement token (préventif)");
            #endif
            RequestToken(force: true);
        }
    }

    public void RequestToken(bool force = false)
    {
#if UNITY_WEBGL && !UNITY_EDITOR
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.Log("[BackendBridge] Demande de token Firebase" + (force ? " (force)" : ""));
        #endif
        GetFirebaseIdTokenJS(gameObject.name, nameof(OnFirebaseIdToken), force ? 1 : 0);
#else
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.LogWarning("[BackendBridge] (Editor) Pas de token WebGL. Simulé.");
        #endif
        _idToken = "EDITOR_DUMMY"; _tokenReady = true;
#endif
    }

    public void OnFirebaseIdToken(string token)
    {
        if (string.IsNullOrEmpty(token))
        {
            Debug.LogWarning("[BackendBridge][AUTH] Token vide reçu - auth pas encore prête");
            return;
        }
        _idToken = token;
        _tokenReady = true;
        _nextTokenRenewAt = Time.realtimeSinceStartup + (55f * 60f); // 55 min
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.Log("[BackendBridge][AUTH] Token prêt");
        #endif
        // Rendre le token disponible aux autres appels UnityWebRequest (fallback)
        try
        {
            PlayerPrefs.SetString("FirebaseAuthToken", token);
            PlayerPrefs.Save();
        }
        catch {}
        AuthReady?.Invoke();
    }

    // =====================
    // Appels protégés
    // =====================
    public void CallMintAuthorization(string playerAddress, int mintCost)
    {
        var payload = JsonUtility.ToJson(new MintReq { playerAddress = playerAddress, mintCost = mintCost });
        string url = serverBase + "/api/mint-authorization";
        AuthorizedPOST(url, payload, nameof(OnMintAuthorizationResponse));
    }

    // (Pas de version stateful: maintenir les appels explicites pour clarté production)
    public void CallUpdatePlayer(string playerAddress, string appKitWallet, int score, int transactionAmount)
    {
        var payload = JsonUtility.ToJson(new UpdateReq {
            playerAddress = playerAddress,
            appKitWallet = appKitWallet,
            scoreAmount = score,
            transactionAmount = transactionAmount
        });
        string url = serverBase + "/api/monad-games-id/update-player";
        AuthorizedPOST(url, payload, nameof(OnUpdatePlayerResponse));
    }

    // (Pas de version stateful)

    void AuthorizedPOST(string url, string jsonPayload, string callback)
    {
#if UNITY_WEBGL && !UNITY_EDITOR
        if (AuthorizedPostJS(url, jsonPayload, gameObject.name, callback) == 0)
        {
            Debug.LogError("[BackendBridge] Échec initial AuthorizedPostJS (paramètres?)");
        }
#else
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.Log("[BackendBridge] (Editor stub POST) " + url + " => " + jsonPayload);
        #endif
#endif
    }

    // Expose le token si nécessaire (fallback pour UnityWebRequest)
    public string GetIdToken()
    {
        return _idToken;
    }

    // =====================
    // Callbacks
    // =====================
    public void OnMintAuthorizationResponse(string raw)
    {
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.Log("[BackendBridge][MINT-AUTH][RAW] " + raw);
        #endif
        var parsed = SafeParse(raw);
        if (parsed != null)
        {
            if (!parsed.ok)
            {
                #if UNITY_EDITOR || DEVELOPMENT_BUILD
                Debug.LogWarning("[BackendBridge][MINT-AUTH] Statut=" + parsed.status + " error=" + parsed.error);
                #endif
            }
            else
            {
                #if UNITY_EDITOR || DEVELOPMENT_BUILD
                Debug.Log("[BackendBridge][MINT-AUTH] OK statut=" + parsed.status + " body=" + Truncate(parsed.body));
                #endif
            }
        }
    }

    public void OnUpdatePlayerResponse(string raw)
    {
        #if UNITY_EDITOR || DEVELOPMENT_BUILD
        Debug.Log("[BackendBridge][UPDATE][RAW] " + raw);
        #endif
        var parsed = SafeParse(raw);
        if (parsed != null)
        {
            if (!parsed.ok)
            {
                #if UNITY_EDITOR || DEVELOPMENT_BUILD
                Debug.LogWarning("[BackendBridge][UPDATE] Statut=" + parsed.status + " error=" + parsed.error);
                #endif
            }
            else
            {
                #if UNITY_EDITOR || DEVELOPMENT_BUILD
                Debug.Log("[BackendBridge][UPDATE] OK statut=" + parsed.status + " body=" + Truncate(parsed.body));
                #endif
            }
        }
    }

    GenericPostResult SafeParse(string raw)
    {
        try { return JsonUtility.FromJson<GenericPostResult>(raw); }
        catch { return null; }
    }

    string Truncate(string s, int max = 180)
    {
        if (string.IsNullOrEmpty(s)) return s;
        return s.Length <= max ? s : s.Substring(0, max) + "...";
    }
}
