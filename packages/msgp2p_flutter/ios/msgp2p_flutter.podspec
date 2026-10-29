Pod::Spec.new do |s|
  s.name             = 'msgp2p_flutter'
  s.version          = '1.0.0'
  s.summary          = 'Thin native CoreBluetooth and Wi-Fi Aware adapters for msgp2p.'
  s.description      = <<-DESC
Flutter plugin providing thin native BLE (CoreBluetooth central/peripheral, L2CAP CoC, GATT fallback)
and Wi-Fi Aware (iOS 26+ WiFiAware framework) byte-level adapters for msgp2p.
                       DESC
  s.homepage         = 'https://msgp2p.squares.net'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'msgp2p Contributors' => 'msgp2p_admin@msgp2p.squares.net' }
  s.source           = { :path => '.' }
  s.source_files     = 'Classes/**/*'
  s.dependency 'Flutter'
  s.frameworks       = 'Security'
  s.platform         = :ios, '14.0'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version    = '5.9'

  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'Tests/**/*'
  end
end
