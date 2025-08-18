using Photon.Pun;
using UnityEngine;
using Photon.Pun;
using System.Collections.Generic;

[RequireComponent(typeof(Rigidbody2D))]
public class ShellCollisionHandler : MonoBehaviourPun
{
    [SerializeField] private LayerMask collisionLayers;

    [Header("Explosion par Raycast (shell)")]
    [SerializeField] private float explosionRadius = 2f;
    [Header("Dégâts")]
    [SerializeField] private float normalDamage = 25f;
    [SerializeField] private float precisionDamage = 50f;
    [SerializeField] private LayerMask tankLayerMask;

    [Header("Ricochet Settings")]
    [SerializeField] private LayerMask ricochetLayerMask;
    [SerializeField] private int maxRicochets = 2;
    private bool canRicochet = false;
    private int ricochetsRemaining;

    [Header("Explosive Shot Settings")]
    [SerializeField] private float explosiveRadius = 4f;
    [SerializeField] private float explosiveDamage = 75f;
    [SerializeField] private GameObject explosiveVFXPrefab;
    [SerializeField] private GameObject aoeIndicatorPrefab;
    private bool isExplosiveShot = false;

    [SerializeField] private GameObject particleOnlyExplosionPrefab;

    [Header("Sprites")]
    [SerializeField] private Sprite normalSprite;
    [SerializeField] private Sprite precisionSprite;
    [SerializeField] private Sprite ricochetSprite;
    [SerializeField] private Sprite explosiveSprite;
    
    [Header("Shell Sizes")]
    [SerializeField] private float normalShellScale = 1f;
    [SerializeField] private float precisionShellScale = 1.2f;
    [SerializeField] private float ricochetShellScale = 1.3f;
    [SerializeField] private float explosiveShellScale = 1.5f;
    [SerializeField] private bool autoScaleCollider = true;
    
    [Header("Shell Colors")]
    [SerializeField] private Color normalShellColor = Color.white;
    [SerializeField] private Color precisionShellColor = Color.white;
    [SerializeField] private Color ricochetShellColor = Color.green;
    [SerializeField] private Color explosiveShellColor = Color.red;

    [Header("Trail Settings")]
    [SerializeField] private TrailRenderer trailRenderer;
    [SerializeField] private Color normalTrailColor = Color.blue;
    [SerializeField] private Color precisionTrailColor = Color.red;
    [SerializeField] private Color ricochetTrailColor = Color.green;
    [SerializeField] private Color explosiveTrailColor = new Color(1f, 0.5f, 0f, 1f); // Orange
    [SerializeField] private float normalTrailWidth = 0.1f;
    [SerializeField] private float precisionTrailWidth = 0.2f;
    [SerializeField] private float specialTrailWidth = 0.25f;
    [SerializeField] private float normalTrailTime = 0.3f;
    [SerializeField] private float precisionTrailTime = 0.6f;
    [SerializeField] private float specialTrailTime = 0.8f;

    private SpriteRenderer sr;
    private float explosionDamage;
    private bool isPrecisionShot = false;
    
    private int shooterActorNumber = -1;
    private float spawnTime;
    private Rigidbody2D rb; 

    private void Awake()
    {
        sr = GetComponent<SpriteRenderer>();
        rb = GetComponent<Rigidbody2D>();
        if (trailRenderer == null) trailRenderer = GetComponent<TrailRenderer>();
        
        spawnTime = Time.time;
        
        if (normalSprite != null && sr != null)
            sr.sprite = normalSprite;
            
        SetupTrail(false);
        explosionDamage = normalDamage; 
    }
    
    private float lastPierceCheckTime = 0f;
    private const float PIERCE_CHECK_INTERVAL = 0.05f; // Check every 50ms instead of every frame
    private HashSet<int> hitTankIds = new HashSet<int>(); 
    
    private void Update()
    {
        if (isExplosiveShot && photonView.IsMine && rb != null && Time.time - lastPierceCheckTime > PIERCE_CHECK_INTERVAL)
        {
            CheckForTankPiercing();
            lastPierceCheckTime = Time.time;
        }
    }
    
    private void CheckForTankPiercing()
    {
        Vector2 velocity = rb.velocity;
        if (velocity.magnitude < 0.1f) return; // Not moving
        
        // Cast a ray in the direction of movement
        RaycastHit2D hit = Physics2D.Raycast(transform.position, velocity.normalized, 0.8f, tankLayerMask);
        
        if (hit.collider != null)
        {
            TankHealth2D tankHealth = hit.collider.GetComponentInParent<TankHealth2D>();
            if (tankHealth != null)
            {
                int tankId = tankHealth.photonView.ViewID;
                
                // Don't hit the same tank twice
                if (hitTankIds.Contains(tankId)) return;
                
                // Check if it's not self-damage
                bool isSelfDamage = tankHealth.photonView.Owner != null && photonView.Owner != null && 
                                  tankHealth.photonView.Owner.ActorNumber == photonView.Owner.ActorNumber;
                
                if (!isSelfDamage)
                {
                    // Check shield
                    TankShield tankShield = tankHealth.GetComponent<TankShield>();
                    if (tankShield == null || !tankShield.IsShieldActive() || isPrecisionShot)
                    {
                        // Mark tank as hit
                        hitTankIds.Add(tankId);
                        
                        // Instant kill with high damage
                        int attackerId = photonView.Owner != null ? photonView.Owner.ActorNumber : -1;
                        tankHealth.photonView.RPC("TakeDamageRPC", RpcTarget.All, 999f, attackerId);
                    }
                }
            }
        }
    }

    [PunRPC]
    public void ActivateRicochetRPC()
    {
        canRicochet = true;
        ricochetsRemaining = maxRicochets;
        
        // Update visual appearance
        if (sr != null && ricochetSprite != null)
            sr.sprite = ricochetSprite;
        
        SetupTrailForSpecialShot(ricochetTrailColor);
        ApplyShellScale(ricochetShellScale);
        ApplyShellColor(ricochetShellColor);
        
        // Auto-destroy after 10 seconds to prevent resource accumulation
        Invoke("AutoDestroyRicochetShell", 17f);
        
    }

    [PunRPC]
    public void ActivateExplosiveShotRPC()
    {
        isExplosiveShot = true;
        
        // Update visual appearance
        if (sr != null && explosiveSprite != null)
            sr.sprite = explosiveSprite;
        
        SetupTrailForSpecialShot(explosiveTrailColor);
        ApplyShellScale(explosiveShellScale);
        ApplyShellColor(explosiveShellColor);
    }

    [PunRPC]
    public void SetPrecision(bool isPrecision)
    {
        if (sr == null) sr = GetComponent<SpriteRenderer>();
        if (isPrecision && precisionSprite != null)
            sr.sprite = precisionSprite;
        else if (normalSprite != null)
            sr.sprite = normalSprite;

        explosionDamage = isPrecision ? precisionDamage : normalDamage;
        isPrecisionShot = isPrecision;
        
        SetupTrail(isPrecision);
        
        // Apply appropriate scale and color
        float targetScale = isPrecision ? precisionShellScale : normalShellScale;
        Color targetColor = isPrecision ? precisionShellColor : normalShellColor;
        ApplyShellScale(targetScale);
        ApplyShellColor(targetColor);
    }
    
    private void SetupTrailForSpecialShot(Color trailColor)
    {
        if (trailRenderer == null) return;
        
        trailRenderer.startColor = trailColor;
        trailRenderer.endColor = new Color(trailColor.r, trailColor.g, trailColor.b, 0f);
        trailRenderer.startWidth = specialTrailWidth;
        trailRenderer.endWidth = specialTrailWidth * 0.3f;
        trailRenderer.time = specialTrailTime;
    }
    
    [PunRPC]
    public void SetShooter(int actorNumber)
    {
        shooterActorNumber = actorNumber;
    }
    
    private void SetupTrail(bool isPrecision)
    {
        if (trailRenderer == null) return;
        
        if (isPrecision)
        {
            trailRenderer.startColor = precisionTrailColor;
            trailRenderer.endColor = new Color(precisionTrailColor.r, precisionTrailColor.g, precisionTrailColor.b, 0f);
            trailRenderer.startWidth = precisionTrailWidth;
            trailRenderer.endWidth = precisionTrailWidth * 0.3f;
            trailRenderer.time = precisionTrailTime;
        }
        else
        {
            trailRenderer.startColor = normalTrailColor;
            trailRenderer.endColor = new Color(normalTrailColor.r, normalTrailColor.g, normalTrailColor.b, 0f);
            trailRenderer.startWidth = normalTrailWidth;
            trailRenderer.endWidth = normalTrailWidth * 0.3f;
            trailRenderer.time = normalTrailTime;
        }
    }



    private void OnCollisionEnter2D(Collision2D collision)
    {
        if (!photonView.IsMine) return;

        // For explosive shots, handle tank hits differently (piercing)
        if (isExplosiveShot)
        {
            TankHealth2D tankHealth = collision.collider.GetComponentInParent<TankHealth2D>();
            if (tankHealth != null)
            {
                // Check if it's not self-damage
                bool isSelfDamage = tankHealth.photonView.Owner != null && photonView.Owner != null && 
                                  tankHealth.photonView.Owner.ActorNumber == photonView.Owner.ActorNumber;
                
                if (!isSelfDamage)
                {
                    // Check shield
                    TankShield tankShield = tankHealth.GetComponent<TankShield>();
                    if (tankShield == null || !tankShield.IsShieldActive() || isPrecisionShot)
                    {
                        // Instant kill with high damage
                        int attackerId = photonView.Owner != null ? photonView.Owner.ActorNumber : -1;
                        tankHealth.photonView.RPC("TakeDamageRPC", RpcTarget.All, 999f, attackerId);
                    }
                }
                // Don't stop - continue trajectory through the tank
                return;
            }
        }

        if (Time.time - spawnTime < 0.3f && shooterActorNumber != -1)
        {
            TankHealth2D health = collision.collider.GetComponentInParent<TankHealth2D>();
            if (health != null && health.photonView.Owner != null && 
                health.photonView.Owner.ActorNumber == shooterActorNumber)
            {
                return; 
            }
        }

        // --- Ricochet Logic ---
        if (canRicochet && ricochetsRemaining > 0)
        {
            int layer = 1 << collision.gameObject.layer;
            if ((ricochetLayerMask.value & layer) != 0)
            {
                ricochetsRemaining--;
                
                Vector2 inDirection = rb.velocity;
                Vector2 inNormal = collision.contacts[0].normal;
                Vector2 newVelocity = Vector2.Reflect(inDirection, inNormal);
                
                // Conserver l'élan et même l'amplifier légèrement
                float currentSpeed = inDirection.magnitude;
                float bounceSpeedMultiplier = 0.9f; // Garde 90% de la vitesse
                rb.velocity = newVelocity.normalized * (currentSpeed * bounceSpeedMultiplier);
                
                // Réduire temporairement la gravité pour un rebond plus naturel
                rb.gravityScale = 0.1f;
                Invoke("RestoreGravity", 0.5f);

                // Optional: Play a bounce sound
                SFXManager.Instance.PlaySFX("ricochet_bounce", 0.5f, Random.Range(0.9f, 1.1f));
                return; // Don't explode yet
            }
        }

        int layerMaskCollision = 1 << collision.gameObject.layer;
        bool isValid = (layerMaskCollision & collisionLayers) != 0;
        if (!isValid) return;

        Vector2 explosionPos = transform.position;

        // Normal explosion logic (walls or non-explosive shots)
        // Use explosive shot parameters if active
        float currentExplosionRadius = isExplosiveShot ? explosiveRadius : explosionRadius;
        float currentExplosionDamage = isExplosiveShot ? explosiveDamage : explosionDamage;

        Collider2D[] hits = Physics2D.OverlapCircleAll(explosionPos, currentExplosionRadius, tankLayerMask);
        foreach (var hit in hits)
        {
            TankHealth2D health = hit.GetComponentInParent<TankHealth2D>();
            if (health == null) continue;
            
            string tankOwner = health.photonView.Owner != null ? $"{health.photonView.Owner.NickName} (Actor {health.photonView.Owner.ActorNumber})" : "<null>";
            string shellOwner = photonView.Owner != null ? $"{photonView.Owner.NickName} (Actor {photonView.Owner.ActorNumber})" : "<null>";
            
            bool isSelfDamage = health.photonView.Owner != null && photonView.Owner != null && 
                              health.photonView.Owner.ActorNumber == photonView.Owner.ActorNumber;
            
            if (isSelfDamage) continue;
            
            TankShield tankShield = health.GetComponent<TankShield>();
            if (tankShield != null && tankShield.IsShieldActive() && !isPrecisionShot)
            {
                continue; 
            }
            
            int attackerId = photonView.Owner != null ? photonView.Owner.ActorNumber : -1;
            
            // Ricochet shots should always be instant kill
            float finalDamage = canRicochet ? 999f : currentExplosionDamage;
            health.photonView.RPC("TakeDamageRPC", RpcTarget.All, finalDamage, attackerId);
            
            // Ricochet shots use instant kill damage
        }

        // Choose appropriate explosion effect
        GameObject explosionPrefab = isExplosiveShot && explosiveVFXPrefab != null ? explosiveVFXPrefab : particleOnlyExplosionPrefab;
        
        if (explosionPrefab != null) {
            GameObject explosion = Instantiate(explosionPrefab, explosionPos, Quaternion.identity);
            
            // Scale explosion effect for explosive shots
            if (isExplosiveShot)
            {
                explosion.transform.localScale = Vector3.one * (explosiveRadius / 2f);
            }
            
            Destroy(explosion, 3f);
        }
        
        photonView.RPC("PlayParticlesRPC", RpcTarget.Others, explosionPos);
        
        PhotonNetwork.Destroy(gameObject);
    }

    [PunRPC]
    private void PlayParticlesRPC(Vector2 pos)
    {
        if (particleOnlyExplosionPrefab == null) return;
        Instantiate(particleOnlyExplosionPrefab, pos, Quaternion.identity);
    }

    private void RestoreGravity()
    {
        if (rb != null)
        {
            rb.gravityScale = 1f; // Restaurer la gravité normale
        }
    }
    
    private void ApplyShellScale(float scale)
    {
        // Scale the visual (sprite)
        transform.localScale = Vector3.one * scale;
        
        // Scale the collider if enabled
        if (autoScaleCollider)
        {
            Collider2D collider = GetComponent<Collider2D>();
            if (collider != null)
            {
                // For CircleCollider2D
                CircleCollider2D circleCollider = collider as CircleCollider2D;
                if (circleCollider != null)
                {
                    circleCollider.radius = circleCollider.radius * scale / transform.localScale.x; // Adjust for current scale
                }
                
                // For BoxCollider2D
                BoxCollider2D boxCollider = collider as BoxCollider2D;
                if (boxCollider != null)
                {
                    boxCollider.size = boxCollider.size * scale / transform.localScale.x; // Adjust for current scale
                }
            }
        }
        
        // Debug.Log($"[ShellCollisionHandler] Applied scale {scale} to shell (visual + collider)");
    }
    
    private void ApplyShellColor(Color color)
    {
        if (sr != null)
        {
            sr.color = color;
        }
    }
    
    private void AutoDestroyRicochetShell()
    {
        if (gameObject != null && photonView.IsMine)
        {
            // Debug.Log("[ShellCollisionHandler] Auto-destroying ricochet shell after 10s");
            PhotonNetwork.Destroy(gameObject);
        }
    }

    private void OnDrawGizmosSelected()
    {
        Gizmos.color = Color.red;
        Gizmos.DrawWireSphere(transform.position, explosionRadius);
    }
}