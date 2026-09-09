package ai.rever.boss.kernel

/** Serializes child registration with the start of a reap, including already-preparing spawns. */
internal class ReapSpawnGate {
    private var depth = 0
    private var generation = 0L

    @Synchronized
    fun generation(): Long = generation

    @Synchronized
    fun isReaping(): Boolean = depth > 0

    @Synchronized
    fun beginReap() {
        depth++
        generation++
    }

    @Synchronized
    fun endReap() {
        depth--
    }

    @Synchronized
    fun <T> spawn(expectedGeneration: Long, registerChild: () -> T): T {
        check(depth == 0 && generation == expectedGeneration) { "A reap interrupted plugin startup" }
        return registerChild()
    }
}

internal val reapSpawnGate = ReapSpawnGate()
