using UnityEngine;
using Photon.Pun;

/// <summary>
/// Coin collectible qui donne 2 points au joueur qui le ramasse
/// Compatible PUN2 avec synchronisation réseau
/// </summary>
public class CoinCollectible : MonoBehaviourPun
{
    [Header("Coin Settings")]
    public int coinValue = 2; // Points accordés pour ramasser le coin
    public float rotationSpeed = 90f; // Vitesse de rotation pour l'effet visuel
    
    [Header("Audio")]
    public AudioClip collectSound; // Son joué lors de la collecte
    
    private bool isCollected = false; // Éviter la double collecte
    
    void Start()
    {
        Debug.Log("[COIN] 🪙 Coin spawné avec succès !");
    }
    
    void Update()
    {
        // Rotation continue pour l'effet visuel
        if (!isCollected)
        {
            transform.Rotate(0f, 0f, rotationSpeed * Time.deltaTime);
        }
    }
    
    void OnTriggerEnter2D(Collider2D other)
    {
        // Vérifier si c'est un tank joueur et éviter la double collecte
        if (isCollected) return;
        
        // Vérifier si l'objet qui touche est un tank (pas un shell)
        // Exclure les shells qui ont un ShellCollisionHandler
        ShellCollisionHandler shellHandler = other.GetComponent<ShellCollisionHandler>();
        if (shellHandler != null) return; // C'est un shell, on ignore
        
        // Vérifier que c'est bien un tank avec TankMovement2D
        TankMovement2D tankMovement = other.GetComponent<TankMovement2D>();
        if (tankMovement == null) return; // Pas un tank
        
        // Vérifier si l'objet qui touche est un tank avec PhotonView
        PhotonView tankPhotonView = other.GetComponent<PhotonView>();
        if (tankPhotonView == null) return;
        
        // Seul le propriétaire du tank peut collecter (évite les conflits réseau)
        if (!tankPhotonView.IsMine) return;
        
        Debug.Log($"[COIN] 🪙 Coin collecté par {tankPhotonView.Owner.NickName} (ActorNumber: {tankPhotonView.Owner.ActorNumber})");
        
        // Marquer comme collecté immédiatement pour éviter la double collecte
        isCollected = true;
        
        // Appeler l'RPC pour collecter le coin sur tous les clients
        photonView.RPC("CollectCoinRPC", RpcTarget.All, tankPhotonView.Owner.ActorNumber);
    }
    
    [PunRPC]
    void CollectCoinRPC(int collectorActorNumber)
    {
        Debug.Log($"[COIN] 🪙 CollectCoinRPC appelé pour ActorNumber: {collectorActorNumber}");
        
        // Jouer le son de collecte localement sur chaque client
        if (collectSound != null && SFXManager.Instance != null && SFXManager.Instance.audioSource != null)
        {
            SFXManager.Instance.audioSource.PlayOneShot(collectSound, 0.7f);
        }
        
        // Ajouter les points au collecteur (seulement sur Master Client)
        if (PhotonNetwork.IsMasterClient && ScoreManager.Instance != null)
        {
            ScoreManager.Instance.AddScore(collectorActorNumber, coinValue);
            Debug.Log($"[COIN] ✅ {coinValue} points ajoutés à ActorNumber {collectorActorNumber}");
        }
        
        // Détruire le coin sur tous les clients
        if (PhotonNetwork.IsMasterClient)
        {
            PhotonNetwork.Destroy(gameObject);
        }
    }
}
