#include<ndis.h>
#include<ntddk.h>
#include<fwpmk.h>
#include<malloc.h>

#define INITGUID

#include<guiddef.h>
#include<fwpmu.h>
#include<fwpsk.h>
#include<rpc.h>

#define TAG_NAME_NOTIFY "data"
#pragma comment(lib,"Rpcrt4.lib")

PDEVICE_OBJECT DeviceObject = NULL;
HANDLE EngineHandle = NULL;
UINT32 RegCalloutId = 0, AddCalloutId;
UINT64 filterid = 0;
DEFINE_GUID(WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID, 0xd9fc32, 0x6fb2, 0x4504, 0x91, 0xce, 0xa9, 0x7c, 0x3c, 0x32, 0xad, 0x36);
DEFINE_GUID(WFP_SAMPLE_SUB_LAYER_GUID, 0x6a5132, 0x36d1, 0x4881, 0xbc, 0xf0, 0xac, 0xeb, 0x4c, 0x04, 0xc2, 0x1c);




VOID UnInitWfp() {


	if (EngineHandle != NULL) {
		if (filterid != 0) {
			FwpmFilterDeleteById(EngineHandle, filterid);
			FwpmSubLayerDeleteByKey(EngineHandle, &WFP_SAMPLE_SUB_LAYER_GUID);
		}
	}
	if (AddCalloutId != 0) {

		FwpmCalloutDeleteById(EngineHandle, AddCalloutId);
	}

	if (RegCalloutId != 0) {
		FwpsCalloutUnregisterById(RegCalloutId);
	}

	FwpmEngineClose(EngineHandle);


}


VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	UnInitWfp();
	IoDeleteDevice(DeviceObject);
	KdPrint(("Unload \r\n"));


}

NTSTATUS NotifyCallback(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterkey, FWPS_FILTER* filter)
{
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(filterkey);
	UNREFERENCED_PARAMETER(type);
	return STATUS_SUCCESS;


}

VOID FlowDeleteCallback(UINT16 layerid, UINT32 calloutid, UINT64 flowcontext)
{
	UNREFERENCED_PARAMETER(flowcontext);
	UNREFERENCED_PARAMETER(calloutid);
	UNREFERENCED_PARAMETER(layerid);



}

//
void FilterCallback(
	const FWPS_INCOMING_VALUES0* inFixedValuesValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaData,
	void* layerData,
	const void* context,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut)
{
	
	ULONG LocalIp, RemoteIp;
	ULONG LocalPort, RemotePort;
	/*//ULONG targetIp = 0x2d2729df;
	NET_BUFFER_LIST* net_buffer_list = NULL;
	NET_BUFFER* netBuffer = NULL;
	MDL* mdl;
	ULONG dataLength = 0;
	*/
	LocalIp = inFixedValuesValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_ADDRESS].value.uint32;
	//FWPS_FIELDS_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;

	RemoteIp = inFixedValuesValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_ADDRESS].value.uint32;
	LocalPort = inFixedValuesValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_LOCAL_PORT].value.uint32;
	RemotePort = inFixedValuesValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint32;
	KdPrint(("LocalIP is %u.%u.%u.%u:%u --- RemoteIP is %u.%u.%u.%u:%u\r\n",
		(LocalIp >> 24) & 0xff, (LocalIp >> 16) & 0xff, (LocalIp >> 8) & 0xff, (LocalIp) & 0xff,
		LocalPort,
		(RemoteIp >> 24) & 0xff, (RemoteIp >> 16) & 0xff, (RemoteIp >> 8) & 0xff, (RemoteIp) & 0xff,
		RemotePort
		));
	inFixedValuesValues->incomingValue[FWPS_FIELD_STREAM_V4_IP_REMOTE_PORT].value.uint32 = 12345;
	//SIZE_T bytes;
	FWPS_STREAM_CALLOUT_IO_PACKET* packet;
	FWPS_STREAM_DATA* streamdata;

	//UCHAR* string;// 2001] = { 0 };
	BYTE* stream = NULL;
	
	//ULONG length = 0;

	packet = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;

	RtlZeroMemory(classifyOut, sizeof(FWPS_CLASSIFY_OUT));
	streamdata = packet->streamData;
	packet->streamAction = FWPS_STREAM_ACTION_NONE;
	classifyOut->actionType = FWP_ACTION_PERMIT;

	UNREFERENCED_PARAMETER(inMetaData);
	UNREFERENCED_PARAMETER(inFixedValuesValues);
	UNREFERENCED_PARAMETER(context);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(filter);
	//UNREFERENCED_PARAMETER(layerData);

	SIZE_T streamLength = streamdata->dataLength;
	SIZE_T byteCopied = 0;
	
		//if ((streamdata->flags & FWPS_STREAM_FLAG_RECEIVE || streamdata->flags & FWPS_STREAM_FLAG_RECEIVE_EXPEDITED || streamdata->flags & FWPS_STREAM_FLAG_SEND || streamdata->flags & FWPS_STREAM_FLAG_SEND_EXPEDITED)) {
			if (streamLength != 0) {
				stream = (BYTE*)ExAllocatePoolWithTag(NonPagedPool,streamLength,1);

			
			KdPrint(("Data Length %ld\r\n", streamdata->dataLength));
		//	string = (UCHAR*)_malloca(streamdata->dataLength * sizeof(UCHAR));

//			length = (ULONG)streamdata->dataLength <= 2000 ? (ULONG)streamdata->dataLength : 2000;
			FwpsCopyStreamDataToBuffer(streamdata, stream, streamLength, &byteCopied);
			KdPrint(("Data is %S\r\n", stream));
			//_freea(string);
			ExFreePoolWithTag(stream,1);
		}
	//}

//	KdPrint(("Data is Here\r\n"));

	if (filter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT) {
		classifyOut->actionType &= FWPS_RIGHT_ACTION_WRITE;
		//classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
	}

}








/*VOID NTAPI classifyFn(const FWPS_INCOMING_VALUES0* Values, const FWPS_INCOMING_METADATA_VALUES0 MetaData, const PVOID layerdata, const void* context, const FWPS_FILTER* filter, UINT64 flowcontext, FWPS_CLASSIFY_OUT* classifyout)
{
}*/
NTSTATUS WfpOpenEngine()
{

	return FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &EngineHandle);

}



NTSTATUS example_notify(
	FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	const GUID* filterKey,
	const FWPS_FILTER* filter)
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	switch (notifyType) {
	case FWPS_CALLOUT_NOTIFY_ADD_FILTER:
		DbgPrint("A new filter has registered Example Callout as its action");
		break;
	case FWPS_CALLOUT_NOTIFY_DELETE_FILTER:
		DbgPrint("A filter that uses Example Callout has just been deleted");
		break;
	}
	return status;
}



NTSTATUS WfpRegisterCallout()
{
	FWPS_CALLOUT Callout = { 0 };

	Callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	Callout.flags = 0;
	Callout.classifyFn = FilterCallback; //example_classify;// classifyFn;// FilterCallback;
	Callout.notifyFn = NotifyCallback;


	Callout.flowDeleteFn = FlowDeleteCallback;
	return FwpsCalloutRegister(DeviceObject, &Callout, &RegCalloutId);


}


NTSTATUS WfpAddCallout()
{
	FWPM_CALLOUT callout = { 0 };


	callout.flags = 0;
	callout.displayData.name = L"EstablishedCalloutName";
	callout.displayData.description = L"EstablishedCalloutName";
	callout.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	callout.applicableLayer = FWPM_LAYER_STREAM_V4;// FWPM_LAYER_INBOUND_TRANSPORT_V4;// FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
	if (EngineHandle != NULL) {

		KdPrint(("NOY NULjjjjjL\r\n"));
	}
	else {
		KdPrint(("NULLLLLLLL\r\n"));
	}
	return FwpmCalloutAdd(EngineHandle, &callout, NULL, &AddCalloutId);


}

NTSTATUS WpfAddSublayer()
{
	FWPM_SUBLAYER sublayer = { 0 };
	//sublayer.subLayerKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;
	sublayer.displayData.name = L"Establishedsublayername";
	sublayer.displayData.description = L"Establishedsublayername";
	sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
	//sublayer.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID; // WFP_SAMPLE_SUB_LAYER_GUID;
	sublayer.weight = 65500;



	if (EngineHandle != NULL) {

		KdPrint(("NOY NULjjjjjL\r\n"));
	}
	else {
		KdPrint(("NULLLLLLLL\r\n"));
	}


	KdPrint(("%ld-%d-%d\r\n", WFP_SAMPLE_SUB_LAYER_GUID.Data1, WFP_SAMPLE_SUB_LAYER_GUID.Data2, WFP_SAMPLE_SUB_LAYER_GUID.Data3));

	KdPrint(("%ld-%d-%d\r\n", sublayer.subLayerKey.Data1, sublayer.subLayerKey.Data2, sublayer.subLayerKey.Data3));

	return FwpmSubLayerAdd(EngineHandle, &sublayer, NULL);



}

NTSTATUS WfpAddFilter()
{
	KdPrint(("%ld-%d-%d\r\n", WFP_SAMPLE_SUB_LAYER_GUID.Data1, WFP_SAMPLE_SUB_LAYER_GUID.Data2, WFP_SAMPLE_SUB_LAYER_GUID.Data3));

	//DWORD result;
	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION condition[1] = { 0 };
	//FWP_V4_ADDR_AND_MASK AddrandMask = { 0 };
	filter.displayData.name = L"Establishedsublayername";
	filter.displayData.description = L"Establishedsublayername";
	filter.layerKey = FWPM_LAYER_STREAM_V4;// FWPM_LAYER_INBOUND_TRANSPORT_V4;// FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4;
	filter.subLayerKey = WFP_SAMPLE_SUB_LAYER_GUID;
	filter.weight.type = FWP_EMPTY;
	filter.numFilterConditions = 1;

	KdPrint(("%ld-%d-%d\r\n", WFP_SAMPLE_SUB_LAYER_GUID.Data1, WFP_SAMPLE_SUB_LAYER_GUID.Data2, WFP_SAMPLE_SUB_LAYER_GUID.Data3));

	filter.filterCondition = condition;
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = WFP_SAMPLE_ESTABLISHED_CALLOUT_V4_GUID;

	condition[0].fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;// ADDRESS;
	condition[0].matchType = FWP_MATCH_LESS_OR_EQUAL;
	condition[0].conditionValue.type = FWP_UINT16;
	//condition[0].conditionValue.v4AddrMask = &AddrandMask;
	condition[0].conditionValue.uint16 = 65000;

	//result = FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);
	//KdPrint(("%ld\r\n", result));

	return  FwpmFilterAdd(EngineHandle, &filter, NULL, &filterid);
}


NTSTATUS InitializeWfp()
{

	if (!NT_SUCCESS(WfpOpenEngine())) {
		goto end;
	}

	if (!NT_SUCCESS(WfpRegisterCallout())) {
		goto end;
	}
	if (!NT_SUCCESS(WfpAddCallout())) {
		KdPrint(("3\r\n"));
		goto end;
	}

	if (!NT_SUCCESS(WpfAddSublayer())) {
		KdPrint(("4\r\n"));
		goto end;

	}

	if (!NT_SUCCESS(WfpAddFilter())) {
		KdPrint(("5\r\n"));
		goto end;
	}
	return STATUS_SUCCESS;
end:
	UnInitWfp();
	return STATUS_UNSUCCESSFUL;

}




extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	DriverObject->DriverUnload = Unload;
	UNREFERENCED_PARAMETER(RegistryPath);

	status = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);

	if (!NT_SUCCESS(status)) {
		return status;

	}
	KdPrint(("Creatingg device SUCCESS \r\n"));
	status = InitializeWfp();

	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(DeviceObject);

	}

	return status;
}
