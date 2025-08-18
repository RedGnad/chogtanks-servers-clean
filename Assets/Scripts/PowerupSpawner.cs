using UnityEngine;
using Photon.Pun;
using System.Collections;

public class PowerupSpawner : MonoBehaviourPun
{
    [Header("Spawn Settings")]
    [SerializeField] private Transform[] spawnPoints;
    [SerializeField] private float spawnInterval = 30f; // 30 seconds between spawns
    [SerializeField] private int maxPowerupsInScene = 3;
    
    [Header("Powerup Prefabs (must be in Resources/Powerups/)")]
    [SerializeField] private string[] powerupPrefabNames = {
        "RicochetPowerup",
        "ExplosivePowerup", 
        "CloakPowerup"
    };
    
    private int currentPowerupCount = 0;
    
    void Start()
    {
        // Only master client spawns power-ups
        if (PhotonNetwork.IsMasterClient)
        {
            StartCoroutine(SpawnPowerupsRoutine());
        }
    }
    
    void OnEnable()
    {
        // Listen for master client changes
        PhotonNetwork.NetworkingClient.EventReceived += OnMasterClientSwitched;
    }
    
    void OnDisable()
    {
        PhotonNetwork.NetworkingClient.EventReceived -= OnMasterClientSwitched;
    }
    
    private void OnMasterClientSwitched(ExitGames.Client.Photon.EventData eventData)
    {
        if (eventData.Code == 208) // Master client switched event
        {
            if (PhotonNetwork.IsMasterClient)
            {
                StartCoroutine(SpawnPowerupsRoutine());
            }
        }
    }
    
    private IEnumerator SpawnPowerupsRoutine()
    {
        while (PhotonNetwork.IsMasterClient)
        {
            yield return new WaitForSeconds(spawnInterval);
            
            if (currentPowerupCount < maxPowerupsInScene && spawnPoints.Length > 0)
            {
                SpawnRandomPowerup();
            }
        }
    }
    
    private void SpawnRandomPowerup()
    {
        if (powerupPrefabNames.Length == 0 || spawnPoints.Length == 0) return;
        
        // Choose random powerup and spawn point
        string randomPowerup = powerupPrefabNames[Random.Range(0, powerupPrefabNames.Length)];
        Transform randomSpawnPoint = spawnPoints[Random.Range(0, spawnPoints.Length)];
        
        // Check if spawn point is clear
        Collider2D existingPowerup = Physics2D.OverlapCircle(randomSpawnPoint.position, 2f);
        if (existingPowerup != null && existingPowerup.GetComponent<MonoBehaviourPun>() != null)
        {
            return; // Spawn point occupied
        }
        
        // Spawn the powerup
        string prefabPath = "Powerups/" + randomPowerup;
        GameObject powerup = PhotonNetwork.Instantiate(prefabPath, randomSpawnPoint.position, Quaternion.identity);
        
        if (powerup != null)
        {
            currentPowerupCount++;
            Debug.Log($"[PowerupSpawner] Spawned {randomPowerup} at {randomSpawnPoint.name}. Total: {currentPowerupCount}");
            
            // Listen for powerup destruction to decrease count
            StartCoroutine(WaitForPowerupDestruction(powerup));
        }
    }
    
    private IEnumerator WaitForPowerupDestruction(GameObject powerup)
    {
        while (powerup != null)
        {
            yield return new WaitForSeconds(1f);
        }
        
        currentPowerupCount--;
        Debug.Log($"[PowerupSpawner] Powerup destroyed. Remaining: {currentPowerupCount}");
    }
    
    // Method to manually spawn a specific powerup (for testing)
    [ContextMenu("Spawn Random Powerup")]
    public void SpawnRandomPowerupManual()
    {
        if (PhotonNetwork.IsMasterClient)
        {
            SpawnRandomPowerup();
        }
    }
}
