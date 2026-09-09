package ai.rever.boss.kernel

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReapSpawnGateTest {
    @Test
    fun `overlapping reaps keep admission closed until both finish`() {
        val gate = ReapSpawnGate()
        gate.beginReap()
        gate.beginReap()
        gate.endReap()
        assertTrue(gate.isReaping())
        assertFailsWith<IllegalStateException> { gate.spawn(gate.generation()) { error("must not spawn") } }
        gate.endReap()
        assertFalse(gate.isReaping())
        assertTrue(gate.spawn(gate.generation()) { true })
    }

    @Test
    fun `a spawn prepared before a completed reap is refused`() {
        val gate = ReapSpawnGate()
        val generation = gate.generation()
        gate.beginReap()
        gate.endReap()
        assertFailsWith<IllegalStateException> { gate.spawn(generation) { error("must not spawn") } }
    }

    @Test
    fun `a reap cannot snapshot before an admitted child registers`() {
        val gate = ReapSpawnGate()
        val generation = gate.generation()
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val reapStarted = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val spawn = executor.submit<Boolean> {
                gate.spawn(generation) {
                    entered.countDown()
                    check(release.await(5, TimeUnit.SECONDS))
                    true
                }
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            val reap = executor.submit {
                reapStarted.countDown()
                gate.beginReap()
            }
            assertTrue(reapStarted.await(5, TimeUnit.SECONDS))
            assertFalse(reap.isDone)
            release.countDown()
            assertTrue(spawn.get(5, TimeUnit.SECONDS))
            reap.get(5, TimeUnit.SECONDS)
            assertTrue(gate.isReaping())
            gate.endReap()
        } finally {
            release.countDown()
            executor.shutdownNow()
        }
    }
}
