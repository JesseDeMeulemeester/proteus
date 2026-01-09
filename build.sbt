name := "Proteus"
version := "0.2"

scalaVersion := "2.12.18"
val spinalVersion = "1.13.0"

fork := true

libraryDependencies ++= Seq(
  "com.github.spinalhdl" %% "spinalhdl-core" % spinalVersion,
  "com.github.spinalhdl" %% "spinalhdl-lib" % spinalVersion,
  "com.github.spinalhdl" %% "spinalhdl-crypto" % "1.2.0-redaes",
  compilerPlugin("com.github.spinalhdl" %% "spinalhdl-idsl-plugin" % spinalVersion)
)
