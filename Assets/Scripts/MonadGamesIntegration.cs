using UnityEngine;
using UnityEngine.Networking;
using System.Collections;
using System;
using System.Collections.Generic;

/// <summary>
/// Intégration avec Monad Games ID pour soumettre scores et transactions
/// après mint/evolve NFT réussis
/// </summary>
public class MonadGamesIDIntegration : MonoBehaviour
{
    [Header("Monad Games ID Contract")]
    private const string MONAD_GAMES_ID_CONTRACT = "0xceCBFF203C8B6044F52CE23D914A1bfD997541A4";
    
    [Header("Score Configuration")]
    private const int MINT_SCORE_POINTS = 2;
    private const int EVOLUTION_LEVEL_2_POINTS = 100;
    private const int EVOLUTION_LEVEL_3_POINTS = 200;
    private const int EVOLUTION_LEVEL_4_POINTS = 300;
    private const int EVOLUTION_LEVEL_5_POINTS = 400;
    
    [Header("Debug")]
    public bool enableDebugLogs = true;
    
    private static MonadGamesIDIntegration instance;
    public static MonadGamesIDIntegration Instance => instance;
    
    void Awake()
    {
        if (instance == null)
        {
            instance = this;
            DontDestroyOnLoad(gameObject);
            DebugLog("[MONAD-GAMES-ID] Integration initialized");
        }
        else
        {
            Destroy(gameObject);
        }
    }
    
    /// <summary>
    /// Appelé après un mint NFT réussi
    /// </summary>
    public void OnNFTMintSuccess(string playerWalletAddress)
    {
        if (string.IsNullOrEmpty(playerWalletAddress))
        {
            DebugLog("[MONAD-GAMES-ID] ERROR: No player wallet address for mint");
            return;
        }
        
        DebugLog($"[MONAD-GAMES-ID] NFT Mint success for {playerWalletAddress}");
        SubmitToMonadGamesID(playerWalletAddress, MINT_SCORE_POINTS, 1, "MINT");
    }
    
    /// <summary>
    /// Appelé après une évolution NFT réussie
    /// </summary>
    public void OnNFTEvolutionSuccess(string playerWalletAddress, int newLevel)
    {
        if (string.IsNullOrEmpty(playerWalletAddress))
        {
            DebugLog("[MONAD-GAMES-ID] ERROR: No player wallet address for evolution");
            return;
        }
        
        int scorePoints = GetEvolutionScorePoints(newLevel);
        DebugLog($"[MONAD-GAMES-ID] NFT Evolution success for {playerWalletAddress} to level {newLevel}");
        SubmitToMonadGamesID(playerWalletAddress, scorePoints, 1, $"EVOLUTION_L{newLevel}");
    }
    
    /// <summary>
    /// Soumet les données au contrat Monad Games ID via appel serveur
    /// </summary>
    private void SubmitToMonadGamesID(string playerAddress, int scoreAmount, int transactionAmount, string actionType)
    {
        DebugLog($"[MONAD-GAMES-ID] Submitting {actionType}: player={playerAddress}, score={scoreAmount}, tx={transactionAmount}");
        
        // Lancer la coroutine pour soumettre via serveur
        StartCoroutine(SubmitToServerCoroutine(playerAddress, scoreAmount, transactionAmount, actionType));
    }
    
    /// <summary>
    /// Coroutine pour soumettre au serveur backend qui appellera Monad Games ID
    /// </summary>
    private IEnumerator SubmitToServerCoroutine(string playerAddress, int scoreAmount, int transactionAmount, string actionType)
    {
        yield return new WaitForSeconds(0.5f); // Petit délai pour s'assurer que tout est stable
        
        DebugLog($"[MONAD-GAMES-ID] Sending request to backend server for updatePlayerData");
        
        // Créer le payload JSON pour le serveur
        var payload = new {
            playerAddress = playerAddress,
            scoreAmount = scoreAmount,
            transactionAmount = transactionAmount,
            actionType = actionType
        };
        
        string jsonPayload = JsonUtility.ToJson(payload);
        DebugLog($"[MONAD-GAMES-ID] Payload: {jsonPayload}");
        
        // URL du serveur signature-server étendu avec endpoint Monad Games ID
        string serverEndpoint = "https://chogtanks-signature-server.onrender.com/api/monad-games-id/update-player";
        
        using (UnityWebRequest request = new UnityWebRequest(serverEndpoint, "POST"))
        {
            byte[] bodyRaw = System.Text.Encoding.UTF8.GetBytes(jsonPayload);
            request.uploadHandler = new UploadHandlerRaw(bodyRaw);
            request.downloadHandler = new DownloadHandlerBuffer();
            request.SetRequestHeader("Content-Type", "application/json");
            
            yield return request.SendWebRequest();
            
            if (request.result == UnityWebRequest.Result.Success)
            {
                DebugLog($"[MONAD-GAMES-ID] SUCCESS! {actionType} submitted to Monad Games ID via server");
                DebugLog($"[MONAD-GAMES-ID] Server response: {request.downloadHandler.text}");
                DebugLog($"[MONAD-GAMES-ID] Player: {playerAddress}, Score: +{scoreAmount}, Transactions: +{transactionAmount}");
                
                // Optionnel: Afficher une notification à l'utilisateur
                ShowSuccessNotification(actionType, scoreAmount);
            }
            else
            {
                DebugLog($"[MONAD-GAMES-ID] ERROR: Failed to submit {actionType} to server: {request.error}");
                DebugLog($"[MONAD-GAMES-ID] Response code: {request.responseCode}");
                DebugLog($"[MONAD-GAMES-ID] Response: {request.downloadHandler.text}");
            }
        }
    }
    
    /// <summary>
    /// Calcule les points de score selon le niveau d'évolution
    /// </summary>
    private int GetEvolutionScorePoints(int targetLevel)
    {
        return targetLevel switch
        {
            2 => EVOLUTION_LEVEL_2_POINTS,
            3 => EVOLUTION_LEVEL_3_POINTS,
            4 => EVOLUTION_LEVEL_4_POINTS,
            5 => EVOLUTION_LEVEL_5_POINTS,
            _ => 100 // Valeur par défaut
        };
    }
    
    /// <summary>
    /// Affiche une notification de succès (optionnel)
    /// </summary>
    private void ShowSuccessNotification(string actionType, int scorePoints)
    {
        // Ici vous pourriez afficher une UI notification
        DebugLog($"[MONAD-GAMES-ID] 🎉 {actionType} recorded! +{scorePoints} points added to Monad Games ID leaderboard!");
    }
    
    /// <summary>
    /// Méthode de debug avec toggle
    /// </summary>
    private void DebugLog(string message)
    {
        if (enableDebugLogs)
        {
            Debug.Log(message);
        }
    }
    
    /// <summary>
    /// Méthode publique pour tester l'intégration
    /// </summary>
    [ContextMenu("Test Mint Integration")]
    public void TestMintIntegration()
    {
        string testAddress = "0x1234567890123456789012345678901234567890";
        OnNFTMintSuccess(testAddress);
    }
    
    /// <summary>
    /// Méthode publique pour tester l'évolution
    /// </summary>
    [ContextMenu("Test Evolution Integration")]
    public void TestEvolutionIntegration()
    {
        string testAddress = "0x1234567890123456789012345678901234567890";
        OnNFTEvolutionSuccess(testAddress, 2);
    }
}
