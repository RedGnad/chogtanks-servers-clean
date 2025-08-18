using UnityEngine;

public class CameraShake2D : MonoBehaviour
{
    public static CameraShake2D Instance { get; private set; }

    private float shakeMagnitude = 0f;
    private float shakeDuration = 0f;

    // Public property that other scripts can read
    public Vector3 ShakeOffset { get; private set; } = Vector3.zero;

    void Awake()
    {
        if (Instance == null)
        {
            Instance = this;
        }
        else
        {
            Destroy(gameObject);
        }
    }

    void Update()
    {
        if (shakeDuration > 0)
        {
            // Generate shake offset instead of directly modifying position
            ShakeOffset = Random.insideUnitSphere * shakeMagnitude;
            shakeDuration -= Time.deltaTime;
        }
        else
        {
            shakeDuration = 0f;
            ShakeOffset = Vector3.zero;
        }
    }

    public void Shake(float magnitude, float duration)
    {
        shakeMagnitude = magnitude;
        shakeDuration = duration;
        // Debug.Log($"[CameraShake2D] Shake started - Magnitude: {magnitude}, Duration: {duration}");
    }
}
