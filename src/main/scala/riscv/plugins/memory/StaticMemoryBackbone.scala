package riscv.plugins.memory

import riscv._
import spinal.core._
import spinal.lib._

import scala.collection.mutable

class StaticMemoryBackbone(implicit config: Config) extends MemoryBackbone {

  override def finish(): Unit = {
    super.finish()

    pipeline plug new Area {
      externalDBus = master(new MemBus(config.dbusConfig)).setName("dbus")
      
      if (dbusFilters.nonEmpty) {
        var previous_level = internalWriteDBus

        dbusFilters.zipWithIndex.foreach { case (f, i) =>
          if (i < dbusFilters.size - 1) {
            val intermediateDBus = Stream(MemBus(config.dbusConfig)).setName("intermediate_dbus" + i)
            f(null, previous_level, intermediateDBus)

            previous_level = intermediateDBus
          } else {
            f(null, previous_level, externalDBus)
          }
        }
      } else {
        internalWriteDBus <> externalDBus
      }

      dbusObservers.foreach(_(internalWriteDBusStage, internalWriteDBus))
    }
  }

  override def createInternalDBus(
      readStages: Seq[Stage],
      writeStage: Stage
  ): (Seq[MemBus], MemBus) = {
    assert(readStages.size == 1)
    assert(readStages.head == writeStage)

    internalWriteDBusStage = readStages.head

    internalWriteDBusStage plug new Area {
      val dbus = master(new MemBus(config.dbusConfig))
      internalWriteDBus = dbus
    }

    (Seq(internalWriteDBus), internalWriteDBus)
  }

}
