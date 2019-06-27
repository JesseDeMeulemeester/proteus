package riscv.plugins

import riscv._

import spinal.core._
import spinal.lib._

private object Data {
  object MUL extends PipelineData(Bool())
  object MUL_HIGH extends PipelineData(Bool())
  object MULDIV_RS1_SIGNED extends PipelineData(Bool())
  object MULDIV_RS2_SIGNED extends PipelineData(Bool())
  object DIV extends PipelineData(Bool())
  object REM extends PipelineData(Bool())
}

class MulDiv(implicit config: Config) extends Plugin {

  override def getImplementedExtensions = Seq('M')

  override def setup(pipeline: Pipeline): Unit = {
    pipeline.getService[DecoderService].configure(pipeline) {decoder =>
      decoder.addDefault(Map(
        Data.MUL -> False,
        Data.MUL_HIGH -> False,
        Data.DIV -> False,
        Data.REM -> False,
        Data.MULDIV_RS1_SIGNED -> False,
        Data.MULDIV_RS2_SIGNED -> False
      ))

      val mulDecodings = Seq(
        (Opcodes.MUL,    False, True,  True),
        (Opcodes.MULH,   True,  True,  True),
        (Opcodes.MULHSU, True,  True,  False),
        (Opcodes.MULHU,  True,  False, False)
      )

      for ((opcode, high, rs1Signed, rs2Signed) <- mulDecodings) {
        decoder.addDecoding(opcode, InstructionType.R, Map(
          Data.MUL -> True,
          Data.MUL_HIGH -> high,
          Data.MULDIV_RS1_SIGNED -> rs1Signed,
          Data.MULDIV_RS2_SIGNED -> rs2Signed,
          pipeline.data.WRITE_RD -> True
        ))
      }

      val divDecodings = Seq(
        (Opcodes.DIV,  False, True),
        (Opcodes.DIVU, False, False),
        (Opcodes.REM,  True,  True),
        (Opcodes.REMU, True,  False)
      )

      for ((opcode, rem, signed) <- divDecodings) {
        decoder.addDecoding(opcode, InstructionType.R, Map(
          Data.DIV -> True,
          Data.REM -> rem,
          Data.MULDIV_RS1_SIGNED -> signed,
          Data.MULDIV_RS2_SIGNED -> signed,
          pipeline.data.WRITE_RD -> True
        ))
      }
    }
  }

  override def build(pipeline: Pipeline): Unit = {
    val mulStage = pipeline.execute

    mulStage plug new Area {
      import mulStage._

      // Multiplication implementation is based on algorithm version 3 from
      // https://www.slideshare.net/TanjarulIslamMishu/multiplication-algorithm-hardware-and-flowchart

      // These variables are declared here to make sure they will be added to
      // the waveform
      val product = Reg(UInt(config.xlen * 2 bits))
      val productH = product(config.xlen * 2 - 1 downto config.xlen)
      val productL = product(config.xlen - 1 downto 0)
      val initMul = Reg(Bool()).init(True)
      val step = Counter(33)
      val multiplicand = UInt(config.xlen + 1 bits)
      val multiplier = UInt(config.xlen bits)
      multiplicand := 0
      multiplier := 0

      when (arbitration.isValid && value(Data.MUL)) {
        arbitration.isReady := False
        arbitration.rs1Needed := True
        arbitration.rs2Needed := True

        val rs1 = value(pipeline.data.RS1_DATA)
        val rs2 = value(pipeline.data.RS2_DATA)

        when (value(Data.MULDIV_RS2_SIGNED) && rs2.asSInt < 0) {
          // If RS2 is signed, RS1 is also signed
          multiplicand := DataTools.signExtend(0 - rs1, config.xlen + 1)
          multiplier := 0 - rs2
        } otherwise {
          when (value(Data.MULDIV_RS1_SIGNED)) {
            multiplicand := DataTools.signExtend(rs1, config.xlen + 1)
          } otherwise {
            multiplicand := DataTools.zeroExtend(rs1, config.xlen + 1)
          }

          multiplier := rs2
        }

        when (initMul) {
          productH := 0
          productL := multiplier
          initMul := False
        } elsewhen (step.willOverflowIfInc) {
          step.increment()
          initMul := True

          arbitration.isReady := True
          output(pipeline.data.RD_DATA) := value(Data.MUL_HIGH) ? productH | productL
          output(pipeline.data.RD_VALID) := True
        } otherwise {
          step.increment()

          val extendedProductH = UInt(config.xlen + 1 bits)

          when (value(Data.MULDIV_RS1_SIGNED) || value(Data.MULDIV_RS2_SIGNED)) {
            extendedProductH := DataTools.signExtend(productH, config.xlen + 1)
          } otherwise {
            extendedProductH := DataTools.zeroExtend(productH, config.xlen + 1)
          }

          val partialSum = UInt(config.xlen + 1 bits)

          when (product.lsb) {
            partialSum := extendedProductH + multiplicand
          } otherwise {
            partialSum := extendedProductH
          }

          product := partialSum @@ product(config.xlen - 1 downto 1)
        }
      }
    }

    val divStage = pipeline.execute

    divStage plug new Area {
      import divStage._

      val quotient = Reg(UInt(config.xlen bits)).init(0)
      val remainder = Reg(UInt(config.xlen bits)).init(0)
      val initDiv = Reg(Bool()).init(True)
      val step = Counter(33)

      when (arbitration.isValid && value(Data.DIV)) {
        arbitration.isReady := False
        arbitration.rs1Needed := True
        arbitration.rs2Needed := True

        val rs1 = value(pipeline.data.RS1_DATA)
        val rs2 = value(pipeline.data.RS2_DATA)
        val signed = value(Data.MULDIV_RS1_SIGNED)
        val dividendIsNeg = signed && (rs1.asSInt < 0)
        val divisorIsNeg = signed && (rs2.asSInt < 0)
        val dividend = dividendIsNeg ? (0 - rs1) | rs1
        val divisor = divisorIsNeg ? (0 - rs2) | rs2

        when (divisor === 0) {
          arbitration.isReady := True
          output(pipeline.data.RD_DATA) :=
            value(Data.REM) ? rs1 | S(-1, config.xlen bits).asUInt
          output(pipeline.data.RD_VALID) := True
        } elsewhen (initDiv) {
          quotient := dividend
          remainder := 0
          initDiv := False
        } elsewhen (step.willOverflowIfInc) {
          val correctedQuotient, correctedRemainder = UInt(config.xlen bits)
          correctedQuotient := quotient
          correctedRemainder := remainder

          when (dividendIsNeg =/= divisorIsNeg) {
            correctedQuotient := 0 - quotient
          }

          when (dividendIsNeg) {
            correctedRemainder := 0 - remainder
          }

          output(pipeline.data.RD_DATA) :=
            value(Data.REM) ? correctedRemainder | correctedQuotient
          output(pipeline.data.RD_VALID) := True
          arbitration.isReady := True
          step.increment()
          initDiv := True
        } otherwise {
          val newRemainder = remainder(config.xlen - 2 downto 0) @@ quotient.msb
          val quotientLsb = Bool()

          when (newRemainder >= divisor) {
            remainder := newRemainder - divisor
            quotientLsb := True
          } otherwise {
            remainder := newRemainder
            quotientLsb := False
          }

          quotient := quotient(config.xlen - 2 downto 0) @@ quotientLsb

          step.increment()
        }
      }
    }
  }
}
