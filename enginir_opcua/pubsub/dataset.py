"""
A DataSet (ds) describes the data of pubsub
"""

from __future__ import annotations

import dataclasses
import uuid
from dataclasses import dataclass, field
from datetime import UTC
from typing import TYPE_CHECKING, Any

from ..common import instantiate_util
from ..common.methods import uamethod
from ..common.node import Node
from ..common.ua_utils import data_type_to_variant_type
from ..pubsub.information_model import PubSubInformationModel
from ..ua import DataSetMetaDataType, FieldMetaData, LocalizedText, ObjectIds, String
from ..ua.attribute_ids import AttributeIds
from ..ua.status_codes import StatusCodes
from ..ua.uaerrors import UaStatusCodeError
from ..ua.uaprotocol_auto import (
    ConfigurationVersionDataType,
    DataSetFieldContentMask,
    DataSetFieldFlags,
    PublishedDataItemsDataType,
    PublishedDataSetDataType,
    PublishedVariableDataType,
)
from ..ua.uatypes import (
    Boolean,
    Byte,
    DataValue,
    DateTime,
    Guid,
    Int16,
    Int32,
    NodeId,
    StatusCode,
    TypeRegistry,
    UInt32,
    ValueRank,
    Variant,
    VariantType,
    default_types,
)
from .uadp import raw_field_to_binary
from .utils import version_time_now

if TYPE_CHECKING:
    from ..server.server import Server


_ABSTRACT_BUILT_IN = (ObjectIds.Number, ObjectIds.Integer, ObjectIds.UInteger)
_DERIVED_BUILT_IN = {
    ObjectIds.Enumeration: VariantType.Int32,
    ObjectIds.IntegerId: VariantType.UInt32,
    ObjectIds.Counter: VariantType.UInt32,
    ObjectIds.Duration: VariantType.Double,
    ObjectIds.NumericRange: VariantType.String,
    ObjectIds.UtcTime: VariantType.DateTime,
    ObjectIds.LocaleId: VariantType.String,
}
_LAST_BUILT_IN_ID = 25


def _get_datatype_or_built_in(
    datatype: NodeId | VariantType | int, built_in: VariantType | None = None
) -> tuple[NodeId, Byte]:
    """
    Returns the DataType NodeId and the corresponding BuiltIn number (Part 14, 6.2.3.2.4). The built-in type of a
    DataType that isn't a namespace 0 type of the table must be given, see `built_in_type_of`.
    """
    if isinstance(datatype, VariantType):
        return NodeId(Int32(datatype)), Byte(datatype.value)
    if isinstance(datatype, int):
        datatype = NodeId(Int32(datatype))
    if built_in is not None:
        return datatype, Byte(built_in.value)
    identifier = datatype.Identifier
    if datatype.NamespaceIndex != 0 or not isinstance(identifier, int):
        return datatype, Byte(0)
    if identifier <= _LAST_BUILT_IN_ID:
        return datatype, Byte(identifier)
    if identifier in _ABSTRACT_BUILT_IN:
        return datatype, Byte(VariantType.Variant.value)
    if identifier in _DERIVED_BUILT_IN:
        return datatype, Byte(_DERIVED_BUILT_IN[identifier].value)
    return datatype, Byte(0)


async def built_in_type_of(server: Server, datatype: NodeId) -> VariantType:
    """The built-in type a DataType is sent as, found through its supertypes in the server's address space"""
    return await data_type_to_variant_type(server.get_node(datatype))


class DataSetField:
    """
    DataSetField class describes the content of a field
    """

    def __init__(self, meta: FieldMetaData | None = None) -> None:
        if meta is None:
            self._meta = FieldMetaData(DataSetFieldId=uuid.uuid4(), FieldFlags=DataSetFieldFlags(0))
        else:
            self._meta = meta

    @classmethod
    def CreateScalar(cls, name: String, datatype: NodeId | VariantType, built_in_type: VariantType | None = None):
        """
        Creates a scalar Field with datatype and name
        """
        datatype_nid, built_in = _get_datatype_or_built_in(datatype, built_in_type)
        meta = FieldMetaData(
            Name=name,
            DataSetFieldId=uuid.uuid4(),
            FieldFlags=DataSetFieldFlags(0),
            BuiltInType=built_in,
            DataType=datatype_nid,
            ValueRank=Int32(-1),
        )
        return cls(meta)

    @classmethod
    def CreateArray(cls, name: String, datatype: NodeId | VariantType, built_in_type: VariantType | None = None):
        """
        Creates a one dimensional array Field with datatype and name
        """
        datatype_nid, built_in = _get_datatype_or_built_in(datatype, built_in_type)
        meta = FieldMetaData(
            Name=name,
            DataSetFieldId=uuid.uuid4(),
            FieldFlags=DataSetFieldFlags(0),
            BuiltInType=built_in,
            DataType=datatype_nid,
            ValueRank=Int32(1),
        )
        return cls(meta)

    def set_promoted(self, promoted: bool) -> None:
        self._meta.FieldFlags = DataSetFieldFlags.PromotedField if promoted else DataSetFieldFlags(0)

    def get_promoted(self) -> bool:
        return True if DataSetFieldFlags.PromotedField in self._meta.FieldFlags else False

    def get_dataset_field_id(self) -> Guid:
        return self._meta.DataSetFieldId

    @property
    def Description(self) -> LocalizedText:
        return self._meta.Description

    @property
    def DataSetFieldId(self) -> Guid:
        return self._meta.DataSetFieldId

    @property
    def Name(self) -> String:
        return self._meta.Name

    @property
    def ArrayDimensions(self) -> list[UInt32]:
        return self._meta.ArrayDimensions

    @property
    def MaxStringLength(self) -> UInt32:
        return self._meta.MaxStringLength

    @property
    def ValueRank(self) -> Int32:
        return self._meta.ValueRank

    @property
    def DataType(self) -> NodeId:
        return self._meta.DataType

    @property
    def BuiltInType(self) -> Byte:
        return self._meta.BuiltInType

    def get_config(self) -> FieldMetaData:
        return self._meta

    def get_datatype_name(self, types: TypeRegistry | None = None) -> str:
        """
        returns the name of DataType, looked up in the registry of the session or server if given
        """
        registry = types if types is not None else default_types
        found = registry.find(self._meta.DataType)
        if found is not None:
            return found.__name__
        if self._meta.BuiltInType != 0:
            return VariantType(self._meta.BuiltInType).name
        return str(self._meta.DataType)


class DataSetMeta:
    """
    Describes a the meta data of a dataset
    """

    def __init__(
        self,
        meta: DataSetMetaDataType,
        dataset_fields: list[DataSetField] | None = None,
    ) -> None:
        self._meta = meta
        if dataset_fields is not None:
            self._fields = dataset_fields
            self._meta.Fields = [ds.get_config() for ds in dataset_fields]
        else:
            self._fields = [DataSetField(cfg) for cfg in self._meta.Fields]

    @classmethod
    def Create(
        cls,
        name: String,
        description: LocalizedText | None = None,
        dataset_fields: list[DataSetField] | None = None,
    ):
        """creates a datasetmeta"""
        meta = DataSetMetaDataType()
        if description is not None:
            meta.Description = description
        if name is not None:
            meta.Name = name
        now = version_time_now()
        meta.ConfigurationVersion.MajorVersion = now
        meta.ConfigurationVersion.MinorVersion = now
        return cls(meta, dataset_fields)

    @property
    def Name(self) -> String:
        return self._meta.Name

    @property
    def Description(self) -> LocalizedText:
        return self._meta.Description

    def _update_version(self, major: bool) -> None:
        """Part 14, 6.2.3.2.6: appending fields changes the minor version, any other change the major version, and
        a new major version is also the minor version"""
        version = self._meta.ConfigurationVersion
        now = version_time_now()
        if major:
            version.MajorVersion = now
        version.MinorVersion = now

    def add_field(self, ds_field: DataSetField | FieldMetaData) -> None:
        if isinstance(ds_field, FieldMetaData):
            ds_field = DataSetField(ds_field)
        self._fields.append(ds_field)
        self._meta.Fields.append(ds_field._meta)
        self._update_version(major=False)

    def add_scalar(self, name: String, datatype: NodeId | VariantType):
        self.add_field(DataSetField.CreateScalar(name, datatype))

    def add_array(self, name: String, datatype: NodeId | VariantType):
        self.add_field(DataSetField.CreateArray(name, datatype))

    def get_field(self, name) -> DataSetField | None:
        return next((f for f in self._fields if f.Name == name), None)

    def remove_field(self, field_name: str) -> None:
        removed = next((f for f in self._fields if f.Name == field_name), None)
        if removed is None:
            return
        self._fields.remove(removed)
        self._meta.Fields = [f for f in self._meta.Fields if f.Name != field_name]
        self._update_version(major=True)

    def get_config(self) -> DataSetMetaDataType:
        return self._meta


def worst_status(values: list[DataValue]) -> StatusCode:
    """The status of a DataSetMessage: the worst status of its fields, Bad before Uncertain (Part 14, 6.2.11.1)"""
    status = StatusCode(UInt32(StatusCodes.Good))
    for v in values:
        if v.StatusCode is None or v.StatusCode.is_good():
            continue
        if status.is_good() or (v.StatusCode.is_bad() and not status.is_bad()):
            status = v.StatusCode
    return status


def select_value_parts(values: list[DataValue], mask: DataSetFieldContentMask) -> list[DataValue]:
    """Copies of the values with only the parts of the DataSetFieldContentMask (Part 14, 6.2.4.2)"""
    ret = []
    for v in values:
        changes: dict[str, Any] = {}
        if DataSetFieldContentMask.StatusCode not in mask:
            changes["StatusCode"] = None
        if DataSetFieldContentMask.SourceTimestamp not in mask:
            changes["SourceTimestamp"] = None
        if DataSetFieldContentMask.SourcePicoSeconds not in mask or DataSetFieldContentMask.SourceTimestamp not in mask:
            changes["SourcePicoseconds"] = None
        if DataSetFieldContentMask.ServerTimestamp not in mask:
            changes["ServerTimestamp"] = None
        if DataSetFieldContentMask.ServerPicoSeconds not in mask or DataSetFieldContentMask.ServerTimestamp not in mask:
            changes["ServerPicoseconds"] = None
        ret.append(dataclasses.replace(v, **changes))
    return ret


class PubSubDataSource:
    """
    Baseclass for all DataSources
    """

    async def get_variant(self) -> tuple[list[Variant], StatusCode, DateTime]:
        """
        return all fields of a dataset as Variants, with the worst status of the fields. A field with a Bad status
        is a Variant holding its StatusCode, one with an Uncertain status a Variant holding its DataValue
        (Part 14, 7.2.4.5.4)
        """
        dt = DateTime.now(UTC)
        vars = await self.on_get_value()
        ret: list[Variant] = []
        st = StatusCode(UInt32(StatusCodes.Good))
        for v in vars:
            status = v.StatusCode
            if status is None or status.is_good():
                ret.append(v.Value)
                continue
            if status.is_bad():
                ret.append(Variant(status, VariantType.StatusCode))
            else:
                ret.append(Variant(v, VariantType.DataValue))
            if st.is_good() or (status.is_bad() and not st.is_bad()):
                st = status
        return (ret, st, dt)

    async def get_value(self, status: bool, server_timestamp: bool, source_timestamp: bool) -> list[DataValue]:
        """
        returns all values for a dataset as DataValues, with only the parts asked for. The values the source holds
        aren't changed.
        """
        ret = []
        for v in await self.on_get_value():
            changes: dict[str, Any] = {}
            if not status:
                changes["StatusCode"] = None
            if not server_timestamp:
                changes["ServerTimestamp"] = None
                changes["ServerPicoseconds"] = None
            if not source_timestamp:
                changes["SourceTimestamp"] = None
                changes["SourcePicoseconds"] = None
            ret.append(dataclasses.replace(v, **changes))
        return ret

    async def get_raw(self, fields: list[FieldMetaData]) -> tuple[list[bytes], StatusCode, DateTime]:
        """
        returns all values for a dataset as raw bytes, padded as the field metadata says (Part 14, 7.2.4.5.11). A
        field without a value is sent as the default value of its type
        """
        dt = DateTime.now(UTC)
        vars = await self.on_get_value()
        ret = []
        st = StatusCode(UInt32(StatusCodes.Good))
        for meta, v in zip(fields, vars, strict=True):
            ret.append(raw_field_to_binary(meta, v.Value))
            if v.StatusCode is not None and not v.StatusCode.is_good():
                st = v.StatusCode
        return ret, st, dt

    async def on_get_value(self) -> list[DataValue]:
        """
        Return all values of the dataset
        """
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)


class PubSubDataSourceDict(PubSubDataSource):
    """
    Implements getting the values to publishing.
    """

    datasources: dict[String, dict[String, DataValue]]

    def __init__(self, ds: DataSetMeta) -> None:
        super().__init__()
        self.datasources = {}
        self.ds = ds

    async def on_get_value(self) -> list[DataValue]:
        """
        returns all values for a dataset
        """
        fields = self.datasources.get(self.ds._meta.Name, {})
        ret = []
        for fld in self.ds._meta.Fields:
            ret.append(
                fields.get(
                    fld.Name,
                    DataValue(StatusCode=StatusCode(UInt32(StatusCodes.BadNoDataAvailable))),
                )
            )
        return ret


class PubSubDataSourceServer(PubSubDataSource):
    """
    Implements getting the values to publishing.
    """

    def __init__(self, server: Server, ds: DataSetMeta, data_items: PublishedDataItemsDataType) -> None:
        super().__init__()
        self.ds = ds
        self.data_items = data_items
        self._server = server

    async def on_get_value(self) -> list[DataValue]:
        """
        returns all values for a dataset
        """
        ret = []
        for pd in self.data_items.PublishedData:
            dv = self._server.read_attribute_value(pd.PublishedVariable, attr=pd.AttributeId)
            if (
                dv.StatusCode is not None
                and not dv.StatusCode.is_good()
                and pd.SubstituteValue.VariantType != VariantType.Null
            ):
                dv = DataValue(
                    pd.SubstituteValue,
                    SourceTimestamp=DateTime.now(UTC),
                    ServerTimestamp=DateTime.now(UTC),
                    StatusCode=StatusCode(UInt32(StatusCodes.UncertainSubstituteValue)),
                )
            ret.append(dv)
        return ret

    async def add_variable(self, published_variable: PublishedVariableDataType):
        self.data_items.PublishedData.append(published_variable)


class PublishedDataSet(PubSubInformationModel):
    """
    Defines a PublishedDataSet for use with a custom datasource (Name => Value via dict)
    """

    def __init__(
        self,
        cfg: PublishedDataSetDataType,
        source: PubSubDataSource | None = None,
        dataset: DataSetMeta | None = None,
    ) -> None:
        super().__init__(False)
        self._data = cfg
        if dataset is not None:
            self.dataset = dataset
            self._data.DataSetMetaData = dataset.get_config()
        else:
            self.dataset = DataSetMeta(self._data.DataSetMetaData)
        if source is not None:
            self._source = source
        else:
            self._source = PubSubDataSourceDict(self.dataset)

    async def _init_information_model(self, parent: Node, server: Server) -> None:
        pds_type = server.get_node(NodeId(Int32(ObjectIds.PublishedDataItemsType)))
        instance = await instantiate_util.instantiate(
            parent,
            pds_type,
            idx=1,
            bname=self._data.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._data.Name, ""),
        )
        pds_obj = instance[0]
        await self._init_node(pds_obj, server)
        await self.set_node_value("0:DataSetMetaData", self.dataset._meta)
        if self._node is not None:
            await self._node.add_variable(
                NodeId(NamespaceIndex=Int16(1)),
                "0:DataSetClassId",
                self.dataset._meta.DataSetClassId,
            )
        else:
            raise RuntimeError("self._node is not initialized")
        # @TODO ExtensionFields
        # @TODO fill method
        # await self.set_node_value("0:PublishedData", self._pubdata)
        # add = await self._node.get_child("0:AddVariables")
        # rem = await self._node.get_child("0:RemoveVariables")

    @classmethod
    def Create(
        cls,
        name: String,
        dataset: DataSetMeta,
        source: PubSubDataSource | None = None,
    ):
        """Allows to construct a PublishDataSet without using the ua structures."""
        s = cls(PublishedDataSetDataType(Name=name), source, dataset)
        return s

    def set_source_custom(self, source: PubSubDataSource):
        """Set the source as custom user defined one"""
        self._source = source

    def get_source(self) -> PubSubDataSource:
        return self._source

    def get_name(self) -> String:
        # @TODO return node value
        return self._data.Name

    def get_config(self) -> PublishedDataSetDataType:
        return self._data

    async def get_meta(self) -> DataSetMeta:
        # @TODO return node value
        return self.dataset


@dataclass
class TargetVariable:
    """
    :ivar Name: Name of the variable in the dataset has to unique in the dataset
    :vartype Name: String
    :ivar SourceNode: NodeId of the variable
    :vartype SourceNode: NodeId
    :ivar ValueRank_: ValueRank of the Variable default Scalar
    :vartype ValueRank_: ValueRank
    :ivar DataType: The datatype, if not provided it extracted by the target node
    :vartype DataType: Optional[NodeId]
    :ivar SubstituteValue: Value to substitute if variable can't be read
    :vartype SubstituteValue: Variant
    :ivar Promoted: Value should be prompoted
    :vartype Promoted: Bool
    """

    Name: String = None
    SourceNode: NodeId = None
    ValueRank: ValueRank = ValueRank.Scalar
    DataType: NodeId | None = None
    SubstituteValue: Variant = field(default_factory=Variant)
    Promoted: Boolean = False


class PublishedDataItems(PubSubInformationModel):
    """
    Defines a PublishedDataItems which links variables in the server AddressSpace
    """

    def __init__(
        self,
        cfg: PublishedDataSetDataType,
        server: Server,
        dataset: DataSetMeta | None = None,
    ) -> None:
        super().__init__(False)
        self._data = cfg
        if dataset is not None:
            self.dataset = dataset
            self._data.DataSetMetaData = dataset.get_config()
        else:
            self.dataset = DataSetMeta(self._data.DataSetMetaData)
        self._published_data: PublishedDataItemsDataType = self._data.DataSetSource
        self._source = PubSubDataSourceServer(server, self.dataset, self._published_data)
        self._server = server

    async def _init_information_model(self, parent: Node, server: Server) -> None:
        pds_type = server.get_node(NodeId(Int32(ObjectIds.PublishedDataItemsType)))
        instance = await instantiate_util.instantiate(
            parent,
            pds_type,
            idx=1,
            bname=self._data.Name,
            instantiate_optional=False,
            dname=LocalizedText(self._data.Name, ""),
        )
        pds_obj = instance[0]
        await self._init_node(pds_obj, server)
        await self.set_node_value("0:DataSetMetaData", self.dataset._meta)
        await self.set_node_value("0:ConfigurationVersion", self.dataset._meta.ConfigurationVersion)
        if self._node is not None:
            await self._node.add_variable(
                NodeId(NamespaceIndex=Int16(1)),
                "0:DataSetClassId",
                self.dataset._meta.DataSetClassId,
            )
        else:
            raise RuntimeError("self._node is not initialized")
        # @TODO ExtensionFields
        # @TODO fill method
        await self.set_node_value(
            ["0:PublishedData"],
            Variant(
                self._published_data.PublishedData,
                VariantType=VariantType.ExtensionObject,
            ),
        )
        meth = await instantiate_util.instantiate(
            pds_obj,
            server.get_node(NodeId(Int32(ObjectIds.PublishedDataItemsType_AddVariables))),
            idx=1,
            bname="0:AddVariables",
            dname=LocalizedText("AddVariables"),
        )
        server.link_method(meth[0], self._add_variables)
        meth = await instantiate_util.instantiate(
            pds_obj,
            server.get_node(NodeId(Int32(ObjectIds.PublishedDataItemsType_RemoveVariables))),
            idx=1,
            bname="0:RemoveVariables",
            dname=LocalizedText("RemoveVariables"),
        )
        server.link_method(meth[0], self._remove_variables)

    @uamethod
    async def _add_variables(
        self,
        config_version: ConfigurationVersionDataType,
        field_name_aliases: list[String],
        promoted_fields: list[Boolean],
        published_variable_data_type: list[PublishedVariableDataType],
    ) -> tuple[ConfigurationVersionDataType, list[StatusCodes]]:
        if self._data.DataSetMetaData.ConfigurationVersion != config_version:
            raise UaStatusCodeError(StatusCodes.BadInvalidState)
        if not field_name_aliases:
            # When empty arguments
            raise UaStatusCodeError(StatusCodes.BadNothingToDo)
        if self._source is None:
            # If no source then no variables can be added
            raise UaStatusCodeError(StatusCodes.BadNotWritable)
        self._source
        self._results = []
        if len(field_name_aliases) != len(promoted_fields) or len(promoted_fields) != len(published_variable_data_type):
            raise UaStatusCodeError(StatusCodes.BadInvalidArgument)
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    @uamethod
    async def _remove_variables(
        self,
        config_version: ConfigurationVersionDataType,
        variables_to_remove: list[UInt32],
    ) -> tuple[ConfigurationVersionDataType, list[StatusCodes]]:
        if self._data.DataSetMetaData.ConfigurationVersion != config_version:
            raise UaStatusCodeError(StatusCodes.BadInvalidState)
        if not variables_to_remove:
            # When empty arguments
            raise UaStatusCodeError(StatusCodes.BadNothingToDo)
        if self._source is None:
            # If no source then no variables can be added
            raise UaStatusCodeError(StatusCodes.BadNotWritable)
        raise UaStatusCodeError(StatusCodes.BadNotImplemented)

    @classmethod
    async def Create(cls, name: String, server: Server, variables: list[TargetVariable]):
        """Allows to construct a PublishedDataItems without using the ua structures."""
        items = PublishedDataItemsDataType()
        fields = []
        for v in variables:
            items.PublishedData.append(
                PublishedVariableDataType(v.SourceNode, AttributeIds.Value, SubstituteValue=v.SubstituteValue)
            )
            flags = DataSetFieldFlags.PromotedField if v.Promoted else DataSetFieldFlags(0)
            meta = FieldMetaData(
                Name=v.Name,
                DataSetFieldId=uuid.uuid4(),
                FieldFlags=flags,
                ValueRank=v.ValueRank,
            )
            if v.DataType is not None:
                datatype = v.DataType
            else:
                datatype = await server.get_node(v.SourceNode).read_data_type()
            built_in = await built_in_type_of(server, datatype)
            meta.DataType, meta.BuiltInType = _get_datatype_or_built_in(datatype, built_in)
            fields.append(meta)
        now = version_time_now()
        meta = DataSetMetaDataType(
            Name=name,
            Fields=fields,
            DataSetClassId=uuid.uuid4(),
            ConfigurationVersion=ConfigurationVersionDataType(MajorVersion=now, MinorVersion=now),
        )
        s = cls(
            PublishedDataSetDataType(Name=name, DataSetSource=items, DataSetMetaData=meta),
            server,
        )
        return s

    def get_source(self) -> PubSubDataSource:
        return self._source

    def get_name(self) -> String:
        # @TODO return node value
        return self._data.Name

    async def get_meta(self) -> DataSetMeta:
        # @TODO return node value
        return self.dataset


@dataclass
class DataSetValue:
    """Value of a subscribed value, with all infos need to process it"""

    Name: String
    Value: DataValue
    Meta: DataSetField
