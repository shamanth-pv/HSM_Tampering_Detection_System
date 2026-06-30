#include <Arduino.h>
#include <Wire.h>

#define I2C_ADDR 0x08
#define SDA_PIN 21
#define SCL_PIN 22
#define TAMPER_PIN 23 

// Structure to send to Pi
struct SecurityPacket {
  uint8_t status;      // 0=Secure, 1=Tamper
  uint8_t event_id;
  uint32_t timestamp;
};

volatile SecurityPacket packet = {0, 0, 0};

// We don't need a complex interrupt for this anymore.
// We will poll the pin state, which is more robust for manual wires.

void requestEvent() {
  Wire.write((uint8_t *)&packet, sizeof(packet));
}

void setup() {
  Serial.begin(115200);
  
  // INPUT_PULLUP: Pin is HIGH (3.3V) by default.
  // Connecting to GND makes it LOW.
  pinMode(TAMPER_PIN, INPUT_PULLUP);
  
  Wire.begin(I2C_ADDR, SDA_PIN, SCL_PIN, 100000);
  Wire.onRequest(requestEvent);
  
  Serial.println(">>> ESP32 Robust Supervisor Ready");
}

void loop() {
  // Read the current physical state of the pin
  int pinState = digitalRead(TAMPER_PIN);

  // Logic: 
  // If Pin is HIGH -> Wire is Disconnected (TAMPER)
  // If Pin is LOW  -> Wire is Connected (SECURE)
  
  if (pinState == HIGH) {
    // Only print/update if we haven't already raised the alarm
    if (packet.status == 0) {
      packet.status = 1;      // Set Alarm
      packet.event_id = 0x01; // Lid Breach
      packet.timestamp = millis();
      
      Serial.println("[ALERT] Wire Disconnected! Sending Alarm...");
      digitalWrite(2, HIGH); // Turn on LED
    }
  } 
  else {
    // The wire is connected (Ground detected)
    // Auto-reset the system to SECURE so we can test again
    if (packet.status == 1) {
      packet.status = 0;      // Clear Alarm
      packet.event_id = 0x00;
      
      Serial.println("[INFO] Wire Reconnected. System Secure.");
      digitalWrite(2, LOW); // Turn off LED
    }
  }

  // Small delay to prevent CPU overload (Debouncing)
  delay(50);
}