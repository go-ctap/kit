package transport

// SmartCardInterface identifies how a smart card is coupled to its reader.
// Detection is best effort and may be unavailable for some PC/SC drivers.
type SmartCardInterface string

const (
	SmartCardInterfaceUnknown     SmartCardInterface = "unknown"
	SmartCardInterfaceContact     SmartCardInterface = "contact"
	SmartCardInterfaceContactless SmartCardInterface = "contactless"
)
