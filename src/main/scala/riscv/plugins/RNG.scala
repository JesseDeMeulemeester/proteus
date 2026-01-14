package riscv.plugins

import riscv._
import spinal.core._
import spinal.lib._
import spinal.crypto.symmetric._
import spinal.crypto.symmetric.aes._

import scala.collection.mutable

/** A FIFO queue to buffer the RNG values.
  *
  * @param queueDepth:
  *   The size of the FIFO queue.
  */
class RngFifo(queueDepth: Int)(implicit config: Config) extends RngBuffer {
  private val rngFifo =
    new StreamFifoLowLatency(dataType = Bits(config.xlen bits), depth = queueDepth) // latency = 0

  rngFifo.io.pop.ready := False
  rngFifo.io.flush := False

  ////////////////////////////
  // Reading from the queue //
  ////////////////////////////

  def read(): UInt = {
    U(rngFifo.io.pop.payload, config.xlen bits)
  }
  def isValid(): Bool = {
    rngFifo.io.pop.valid
  }

  def request(): Unit = {
    rngFifo.io.pop.ready := True
  }

  def flush(): Unit = {
    rngFifo.io.flush := True
  }

  def isFull(): Bool = {
    !rngFifo.io.push.ready
  }

  when(isValid()) {
    rngFifo.io.pop.ready := False
  }

  /////////////////////////////////////
  // Inserting values into the queue //
  /////////////////////////////////////

  def connect(inputStream: Stream[Bits]): Unit = {
    rngFifo.io.push << inputStream
  }
}

private class RngComponent(implicit config: Config) extends Component {
  setDefinitionName("RNG")
}

private class csrRng(implicit config: Config) extends Csr {
  val rgnControl = Reg(UInt(config.xlen bits)).init(0)

  override def read(): UInt = rgnControl
  override def write(value: UInt): Unit = this.rgnControl := value
}

private class csrSeed(implicit config: Config) extends Csr {
  val seedValue = Reg(Bits(config.xlen bits)).init(0)

  override def read(): UInt = seedValue.asUInt
  def readb(): Bits = seedValue
  override def write(value: UInt): Unit = this.seedValue := value.asBits
}

/** AES core in OFB mode to generate random numbers
  *
  * @param aesRounds:
  *   Optional parameter to reduce the number of rounds per AES encryption. Setting this value to
  *   zero (default) will use the standard number of rounds.
  */
private class AESCore(aesRounds: Int = 0) extends Component {
  private val AESconfig = SymmetricCryptoBlockConfig(
    keyWidth = 128 bits,
    blockWidth = 128 bits,
    useEncDec = true
  )

  private val AESOFBconfig = BCMO_Std_Config(
    keyWidth = AESconfig.keyWidth.value,
    blockWidth = AESconfig.blockWidth.value,
    useEncDec = true,
    ivWidth = AESconfig.blockWidth.value
  )

  val io = new Bundle {
    val core = slave(BCMO_Std_IO(AESOFBconfig))
  }

  private val core = new AESCore_Std(128 bits, aesRounds)
  private val chaining = OFB_Std(core.gIO, ENC_DEC, ENCRYPT)

  chaining.io.core <> core.io
  chaining.io.bcmo <> io.core
}

/** Pseudorandom number generator
  *
  * Seeds are generated with AES in counter mode. The IV can be updated through CSRs.
  *
  * Each component that requires random seeds (e.g., cache layer) needs to to register a RngFifo.
  *
  * ```
  *                   (IV ## Counter)
  *                      ___|___
  *             Key --> |  AES  |
  *                     |_______|
  *                         |
  *          _______________|_______________
  *          |         |         |         |
  *        buffer    buffer    buffer    buffer
  *          |_________|_________|_________|
  *                        |
  *                  rngDemuxBuffer
  *                        |
  *         _______________|_______________
  *         |         |          |        |
  *       RNG 0     RNG 1      RNG 2     ...
  *
  * ```
  *
  * @param memoryDepth:
  *   The size of the internal RNG buffer (rngDemuxBuffer)
  * @param allowUninitializedRng:
  *   Whether to allow the RNG to generate random using the default IV. Setting this to `false`
  *   (default) requires the IV to be updated through the RNG Control CSR.
  * @param aesRounds:
  *   Optional parameter to reduce the number of rounds per AES encryption. Setting this value to
  *   zero (default) will use the standard number of rounds.
  */
class Rng(memoryDepth: Int, allowUninitializedRng: Boolean = false, aesRounds: Int = 0)
    extends Plugin[Pipeline]
    with RngService {
  // RNG CSR flags
  private val RNG_DISABLE = 0x1 /* If set, disable the RNG */
  private val RNG_UPDATEIV = 0x2 /* If set, update IV using seed CSRs */

  private val CSR_RNGCONTROL = 0x863
  private val CSR_SEED0 = 0x880
  private val CSR_SEED1 = 0x881
  private val CSR_SEED2 = 0x882
  private val CSR_SEED3 = 0x883

  // https://numbergenerator.org/hex-code-generator#!numbers=1&length=32
  private val INIT_IV = BigInt("A285B576DE50221962EC54E8DBD45F0B", 16)
  private val INIT_KEY = BigInt("A221C97EC9F7CB6805FA3DB538354FC3", 16)
  private val INIT_PT = BigInt("D98A2873E93266C824410C1CD1426C00", 16)

  ////////////////////////
  // RNG queue handling //
  ////////////////////////

  // lazy because pipeline is null at the time of construction.
  private lazy val component = pipeline plug new RngComponent
  private val rngbuffers = mutable.Map[Int, RngBuffer]()
  private var nbrngbuffers = 0;

  /** Register a new RNG buffer.
    *
    * @param rngbuffer:
    *   The RNG buffer to register.
    *
    * @return
    *   The index of the registered RNG buffer.
    */
  override def registerRngBuffer[T <: RngBuffer](rngbuffer: => T): Int = {
    val pluggedRngBuffer = component.plug(rngbuffer)
    val rngbufferindex = nbrngbuffers
    rngbuffers(rngbufferindex) = pluggedRngBuffer

    nbrngbuffers = nbrngbuffers + 1

    rngbufferindex
  }

  /** Get the RNG buffer with the given index.
    *
    * @param id:
    *   The ID of the RNG buffer.
    */
  override def getRngBuffer(id: Int): RngIo = {
    assert(rngbuffers.contains(id))

    val area = component plug new Area {
      val rngIo = master(new RngIo())
      rngIo.setName(s"rng_$id")
      val rng = rngbuffers(id)

      rngIo.rdata := rng.read()
      rngIo.rdata_valid := rng.isValid()
      when(rngIo.rdata_request) {
        rng.request()
      }
    }

    area.rngIo
  }

  override def setup(): Unit = {
    val csrService = pipeline.service[CsrService]

    // The CSR to control the RNG
    csrService.registerCsr(CSR_RNGCONTROL, new csrRng)

    // The CSRs for changing the IV of the RNG
    csrService.registerCsr(CSR_SEED0, new csrSeed)
    csrService.registerCsr(CSR_SEED1, new csrSeed)
    csrService.registerCsr(CSR_SEED2, new csrSeed)
    csrService.registerCsr(CSR_SEED3, new csrSeed)
  }

  override def build(): Unit = {
    val rngComponent = component

    val componentArea = rngComponent plug new Area {
      import rngComponent._

      val csrRngControl = slave(new CsrIo)

      val csrSeed0 = slave(new CsrIo)
      val csrSeed1 = slave(new CsrIo)
      val csrSeed2 = slave(new CsrIo)
      val csrSeed3 = slave(new CsrIo)

      ///////////////////////////////
      // Initialization of the RNG //
      ///////////////////////////////
      private val rngCore = new AESCore(aesRounds)

      // Initial state
      rngCore.io.core.cmd.enc := True
      rngCore.io.core.cmd.mode := BCMO_Std_CmdMode.UPDATE
      rngCore.io.core.cmd.valid := False

      private val rngIV_reg = Reg(UInt(128 bits)) init (INIT_IV)
      private val rngKey_reg = U(INIT_KEY, 128 bits)
      private val rngPt_reg = U(INIT_PT, 128 bits)

      rngCore.io.core.cmd.key := rngKey_reg.asBits
      rngCore.io.core.cmd.iv := rngIV_reg.asBits
      rngCore.io.core.cmd.block := rngPt_reg.asBits

      private val busy = Bool()

      private val rngKeyUpdated = Reg(Bool()) init allowUninitializedRng
      private val rngDisabled = Reg(Bool()) init False

      ///////////////////////////////////////
      //            RNG Memory             //
      ///////////////////////////////////////

      // FIFO_buffer <-> RNG
      val rngPerAES = rngCore.io.core.config.blockWidth >> log2Up(config.xlen)
      val rngBuffer = Seq.fill(rngPerAES)(StreamFifo(Bits(config.xlen bits), 1))
      val rngBufferPush = Vec(rngBuffer.map(_.io.push)) // Vec of push streams
      val rngBufferPop = Vec(rngBuffer.map(_.io.pop)) // Vec of pop streams

      val rngArbiter = StreamArbiterFactory.sequentialOrder.transactionLock.on(rngBufferPop)

      // FIFO_buffer <-> FIFO_LOWLATENCY
      val rngDemuxBuffer = new StreamFifoLowLatency(
        dataType = Bits(config.xlen bits),
        depth = memoryDepth
      ) // latency = 0

      for (i <- 0 until rngPerAES) {
        rngBufferPush(i).valid := rngCore.io.core.rsp.valid & rngKeyUpdated

        // When the seed generation is disabled, replace all seeds with 0.
        when(rngDisabled) {
          rngBufferPush(i).payload := B(0, config.xlen bits)
        } otherwise {
          rngBufferPush(i).payload := rngCore.io.core.rsp
            .block((config.xlen * i).toInt, config.xlen bits)
        }
      }
      rngDemuxBuffer.io.push << out(rngArbiter)

      // FIFO_LOWLATENCY <-> RngBuffers
      private val selectRngBuffer = Counter(nbrngbuffers, rngDemuxBuffer.io.pop.fire)
      private val outputRngStreams = StreamDemux(rngDemuxBuffer.io.pop, selectRngBuffer, nbrngbuffers)
      private val rngBufferFull = Vec.fill(nbrngbuffers)(Bool)

      // Connect the demuxed stream to all RNG buffers
      for (i <- 0 until nbrngbuffers) {
        rngbuffers(i).connect(outputRngStreams(i))
        rngBufferFull(i) := rngbuffers(i).isFull()
      }

      // Advance the counter when the current buffer is full to avoid stalling the RNG
      private val currentBufferFull = rngBufferFull(selectRngBuffer)
      private val allBuffersFull = rngBufferFull.reduceBalancedTree(_ & _)
      when(currentBufferFull & !allBuffersFull) {
        selectRngBuffer.increment()
      }

      private def initialize(): Unit = {
        rngDemuxBuffer.io.flush := True
        for (i <- 0 until rngPerAES) {
          rngBuffer(i).io.flush := True
        }
        rngCore.io.core.cmd.mode := BCMO_Std_CmdMode.INIT
        rngCore.io.core.cmd.valid := True
      }

      val rngBufferCanAcceptVec = Vec(Bool(), rngPerAES)

      rngDemuxBuffer.io.flush := False
      for (i <- 0 until rngPerAES) {
        rngBuffer(i).io.flush := False
        rngBufferCanAcceptVec(i) := (rngBuffer(i).io.occupancy === 0)
      }

      /** Whether the previous ciphertext has been consumed and we can start a new encryption.
        *
        * @return
        *   Whether the previous value has been consumed
        *
        * @todo:
        *   This wastes 4 cycles by waiting for the `rngDemuxBuffer` to consume the values, causing
        *   the AES core to stall.
        */
      private def canStartEncryption(): Bool = {
        rngBufferCanAcceptVec.reduce(_ & _) && rngKeyUpdated
      }

      private def RNGEncrypt(): Unit = {
        rngCore.io.core.cmd.valid := True
        when(rngCore.io.core.cmd.ready) {
          rngCore.io.core.cmd.valid := False
        }
      }

      busy := rngCore.io.core.cmd.valid

      // TODO: Also check whether we're updating the seed?
      when(canStartEncryption()) {
        RNGEncrypt()
      }

      /////////////////////////
      // Updating seed logic //
      /////////////////////////

      /** Update the seed (i.e., the IV) of the AES engine.
        *
        * The new seed will be taken from the CSR registers.
        */
      private def updateSeed(): Unit = {
        rngIV_reg := (U(0, 96 bits) @@ csrSeed0.read()) |
          (csrSeed1.read() << 32).resized |
          (csrSeed2.read() << 64).resized |
          (csrSeed3.read() << 96).resized

        // Flush the internal RNG demux buffer and any connected RngBuffers to
        // discard stale seeds generated using the old seed
        rngDemuxBuffer.io.flush := True
        for (i <- 0 until nbrngbuffers) {
          rngbuffers(i).flush()
        }

        rngCore.io.core.cmd.mode := BCMO_Std_CmdMode.INIT
        rngCore.io.core.cmd.valid := True
        rngKeyUpdated := True
      }

      // Update IV (from CSR registers)
      when((csrRngControl.read() & RNG_UPDATEIV) =/= 0) {
        updateSeed()

        // Reset bit in CSR
        csrRngControl.write(csrRngControl.read() & ~U(RNG_UPDATEIV, 32 bits))
      }

      // Disable the seed generation. All seeds will be replaced with all 0s.
      private def disableRNG(): Unit = {
        rngDisabled := True
      }

      // Disable RNG (from CSR registers)
      when((csrRngControl.read() & RNG_DISABLE) =/= 0) {
        disableRNG()

        // Reset bit in CSR
        csrRngControl.write(csrRngControl.read() & ~U(RNG_DISABLE, 32 bits))
      }
    }

    pipeline plug new Area {
      val csrService = pipeline.service[CsrService]

      componentArea.csrRngControl <> csrService.getCsr(CSR_RNGCONTROL)

      componentArea.csrSeed0 <> csrService.getCsr(CSR_SEED0)
      componentArea.csrSeed1 <> csrService.getCsr(CSR_SEED1)
      componentArea.csrSeed2 <> csrService.getCsr(CSR_SEED2)
      componentArea.csrSeed3 <> csrService.getCsr(CSR_SEED3)
    }
  }
}
