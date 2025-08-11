using Photon.Pun;
using UnityEngine;
using System.Collections.Generic;
using System.Linq;

[System.Serializable]
public class SFXClip
{
    public string name;
    public AudioClip clip;
    public bool shareInMultiplayer = true;
    public float defaultVolume = 1f;
}

public class SFXManager : MonoBehaviourPun
{
    [Header("Audio Settings")]
    public AudioSource audioSource;
    public float masterVolume = 1f;
    
    [Header("Multiplayer Audio")]
    [Range(0f, 1f)]
    public float multiplayerVolumeMultiplier = 0.5f;
    
    [Header("SFX Configuration")]
    public SFXClip[] sfxClips;
    
    [Header("Killfeed Sounds")]
    public AudioClip[] killFeedSounds; // Tableau flexible pour les sons de killfeed
    [Range(0f, 1f)]
    public float killFeedVolume = 0.8f; // Volume réglable pour les sons de killfeed
    
    private static SFXManager instance;
    private Dictionary<string, SFXClip> sfxDictionary;
    
    public static SFXManager Instance
    {
        get
        {
            if (instance == null)
                instance = FindObjectOfType<SFXManager>();
            return instance;
        }
    }
    
    void Awake()
    {
        if (instance == null)
        {
            instance = this;
            DontDestroyOnLoad(gameObject);
            InitializeSFXDictionary();
        }
        else if (instance != this)
        {
            Destroy(gameObject);
        }
    }
    
    void Start()
    {
        if (audioSource == null)
            audioSource = GetComponent<AudioSource>();
    }
    
    private void InitializeSFXDictionary()
    {
        sfxDictionary = new Dictionary<string, SFXClip>();
        foreach (var sfxClip in sfxClips)
        {
            if (!string.IsNullOrEmpty(sfxClip.name) && sfxClip.clip != null)
            {
                sfxDictionary[sfxClip.name] = sfxClip;
            }
        }
    }
    
    public void PlaySFX(string sfxName, float volumeMultiplier = 1f)
    {
        if (string.IsNullOrEmpty(sfxName) || sfxDictionary == null) return;
        
        if (!sfxDictionary.TryGetValue(sfxName, out SFXClip sfxClip))
        {
            Debug.LogWarning($"[SFX] Audio clip not found: {sfxName}");
            return;
        }
        
        float finalVolume = sfxClip.defaultVolume * volumeMultiplier;
        
        if (sfxClip.shareInMultiplayer)
        {
            photonView.RPC("RPC_PlaySFX", RpcTarget.Others, sfxName, finalVolume);
        }
        
        PlayLocalSFX(sfxClip.clip, finalVolume);
    }
    
    private void PlayLocalSFX(AudioClip clip, float volume)
    {
        if (audioSource != null)
        {
            audioSource.PlayOneShot(clip, volume * masterVolume);
        }
    }
    
    [PunRPC]
    void RPC_PlaySFX(string sfxName, float volume)
    {
        if (sfxDictionary != null && sfxDictionary.TryGetValue(sfxName, out SFXClip sfxClip))
        {
            PlayLocalSFX(sfxClip.clip, volume * multiplayerVolumeMultiplier);
        }
    }
    
    public void PlayShieldActivation()
    {
        PlaySFX("shield_activation", 0.8f);
    }
    
    public void PlayExplosion()
    {
        PlaySFX("explosion_big", 1f);
    }
    
    public void PlayWeaponFire()
    {
        PlaySFX("weapon_fire", 0.6f);
    }
    
    public void PlayTankDeath()
    {
        PlaySFX("tank_death", 1f);
    }
    
    public void PlayPowerupPickup()
    {
        PlaySFX("powerup_pickup", 0.7f);
    }
    
    public void PlayRandomKillFeedSoundLocal()
    {
        Debug.Log("[SFX] 🎵 PlayRandomKillFeedSoundLocal() appelé");
        
        // Version simplifiée : joue seulement localement, pas de RPC
        // Le RPC sera géré par ScoreManager pour synchroniser entre tous les joueurs
        
        if (killFeedSounds == null || killFeedSounds.Length == 0)
        {
            Debug.LogWarning("[SFX] ⚠️ Aucun son de killfeed configuré dans l'inspecteur !");
            Debug.LogWarning($"[SFX] killFeedSounds = {(killFeedSounds == null ? "null" : $"array de {killFeedSounds.Length} éléments")}");
            return;
        }
        
        Debug.Log($"[SFX] 🎶 {killFeedSounds.Length} sons de killfeed disponibles");
        
        // Choisir un son aléatoire dans le tableau
        int randomIndex = Random.Range(0, killFeedSounds.Length);
        AudioClip randomClip = killFeedSounds[randomIndex];
        
        Debug.Log($"[SFX] 🎲 Son sélectionné: index {randomIndex}, clip: {(randomClip != null ? randomClip.name : "null")}");
        
        if (randomClip != null && audioSource != null)
        {
            float finalVolume = killFeedVolume * masterVolume;
            Debug.Log($"[SFX] 🔊 Lecture du son '{randomClip.name}' - Volume: {finalVolume} (killFeedVolume: {killFeedVolume}, masterVolume: {masterVolume})");
            
            // Jouer le son localement seulement
            audioSource.PlayOneShot(randomClip, finalVolume);
            
            Debug.Log("[SFX] ✅ Son de killfeed joué avec succès !");
        }
        else
        {
            if (randomClip == null)
                Debug.LogError("[SFX] ❌ Le clip audio sélectionné est null !");
            if (audioSource == null)
                Debug.LogError("[SFX] ❌ AudioSource est null !");
        }
    }
    
    [PunRPC]
    void RPC_PlayKillFeedSFX(int clipIndex, float volume)
    {
        if (killFeedSounds != null && clipIndex >= 0 && clipIndex < killFeedSounds.Length)
        {
            AudioClip clipToPlay = killFeedSounds[clipIndex];
            if (clipToPlay != null)
            {
                PlayLocalSFX(clipToPlay, volume * multiplayerVolumeMultiplier);
            }
        }
    }
}
