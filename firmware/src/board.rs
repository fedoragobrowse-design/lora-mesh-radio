//! Fixed wiring: Pico 2 W GPIO to Adafruit RFM95W #3072.
//! GPIO numbers, not physical pins. See node-wiring.svg + plan table.
//!
//! The default radio-free image never initializes these GPIOs/SPI; the
//! radio module (behind `feature = "radio"`) owns them in the next phase.

/// SPI0 clock (GP18, phys 24) -> SCK.
pub const PIN_SCK: u8 = 18;
/// SPI0 MOSI (GP19, phys 25) -> MOSI.
pub const PIN_MOSI: u8 = 19;
/// SPI0 MISO (GP16, phys 21) <- MISO.
pub const PIN_MISO: u8 = 16;
/// Chip select (GP17, phys 22) -> CS.
pub const PIN_CS: u8 = 17;
/// Reset (GP20, phys 26) -> RST.
pub const PIN_RESET: u8 = 20;
/// Interrupt (GP21, phys 27) <- G0/DIO0.
pub const PIN_DIO0: u8 = 21;

/// Marker that the pin table has been transcribed into code.
pub struct Pins;
impl Pins {
    pub const DESCRIBED: bool = true;
}

// Interrupt bindings: USB + flash DMA + TRNG + SPI DMA + CYW43 PIO/DMA.
// All DMA channels share DMA_IRQ_0 on RP235x; the generated ISR dispatches
// to each listed handler, which filters by its own channel bit. DMA_CH2 =
// flash owner, DMA_CH0/CH1 = SPI0 TX/RX when `feature = "radio"` is
// enabled, DMA_CH3 = CYW43 PIO SPI (WiFi task, radio image only).
embassy_rp::bind_interrupts!(pub struct Irqs {
    USBCTRL_IRQ => embassy_rp::usb::InterruptHandler<embassy_rp::peripherals::USB>;
    PIO0_IRQ_0 => embassy_rp::pio::InterruptHandler<embassy_rp::peripherals::PIO0>;
    DMA_IRQ_0 => embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH0>, embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH1>, embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH2>, embassy_rp::dma::InterruptHandler<embassy_rp::peripherals::DMA_CH3>;
    TRNG_IRQ => embassy_rp::trng::InterruptHandler<embassy_rp::peripherals::TRNG>;
});
