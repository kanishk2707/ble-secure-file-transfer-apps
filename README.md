# project
ABOUT THIS PROJECT:<br />
This project is a secure Bluetooth Low Energy (BLE) file transfer system built with React Native for Android and iOS. It consists of a sender app and a receiver app. The sender enables you to scan for nearby BLE devices, pick any file from your device, and send it in encrypted chunks through a secure, authenticated BLE connection using ephemeral key exchange and AES-GCM encryption. The receiver reconstructs and decrypts the file securely on the other end, ensuring data protection and reliable transfer between devices without requiring internet connectivity.<br />
<br />
SECURE BLE FILE TRANSFER:<br />
  A cross-platform (Android/iOS) React Native project for secure<br /> encrypted file transfer using Bluetooth Low Energy (BLE) with ephemeral key exchange<br /> AES-GCM encryption<br />  chunk-based data transmission.<br />
  <br />
FEATURES:<br />
  BLE device scanning, connection, and chunked data transfer<br />
  file picking from device storage<br />
  Ephemeral Curve25519 key exchange for authentication<br />
  AES-GCM encryption with HKDF-derived key<br />
  Reliable, ACK-based chunk transmission<br />
  Separate sender and receiver apps<br />
  <br />
DEPENDENCIES:<br />
react-native-ble-plx<br />
react-native-document-picke<br />r
tweetnacl<br />
react-native-aes-crypto<br />
buffer<br />
crypto-js<br />
<br />
PERMISSIONS:<br />
ANDROID:<br />
Bluetooth permissions (BLUETOOTH_SCAN, BLUETOOTH_CONNECT, ACCESS_FINE_LOCATION, BLUETOOTH_ADVERTISE)<br />
File storage permissions if needed<br />
<br />
iOS:<br />
Bluetooth usage descriptions (NSBluetoothAlwaysUsageDescription, etc.)<br />
Update AndroidManifest.xml and Info.plist accordingly.<br />

