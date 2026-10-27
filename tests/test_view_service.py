from typing import Any

import pytest

from enginir_opcua import Client, Node, ua
from enginir_opcua.ua.uaerrors import UaStatusCodeError

from .access_rig import AccessRig, make_access_rig  # noqa: F401

HIERARCHICAL = ua.NodeId(ua.ObjectIds.HierarchicalReferences)


def code(value: int) -> ua.StatusCode:
    return ua.StatusCode(value)


def description(
    nodeid: ua.NodeId,
    direction: ua.BrowseDirection = ua.BrowseDirection.Forward,
    reference_type: ua.NodeId | None = None,
    include_subtypes: bool = True,
    node_class_mask: int = 0,
    result_mask: int = ua.BrowseResultMask.All,
) -> ua.BrowseDescription:
    return ua.BrowseDescription(
        NodeId=nodeid,
        BrowseDirection=direction,
        ReferenceTypeId=reference_type if reference_type is not None else ua.NodeId(),
        IncludeSubtypes=include_subtypes,
        NodeClassMask=node_class_mask,
        ResultMask=result_mask,
    )


async def browse(
    client: Client, *descriptions: ua.BrowseDescription, maximum: int = 0, view: ua.ViewDescription | None = None
) -> list[ua.BrowseResult]:
    params = ua.BrowseParameters(RequestedMaxReferencesPerNode=maximum, NodesToBrowse=list(descriptions))
    if view is not None:
        params.View = view
    return await client.uaclient.browse(params)


async def browse_next(client: Client, *tokens: bytes, release: bool = False) -> list[ua.BrowseResult]:
    params = ua.BrowseNextParameters(ReleaseContinuationPoints=release, ContinuationPoints=list(tokens))
    return await client.uaclient.browse_next(params)


def children_of(nodeid: ua.NodeId, **kwargs: Any) -> ua.BrowseDescription:
    return description(nodeid, reference_type=HIERARCHICAL, **kwargs)


async def folder_with_children(rig: AccessRig, name: str, count: int) -> Node:
    folder = await rig.server.nodes.objects.add_folder(rig.node_id(name), name)
    for index in range(count):
        await folder.add_variable(rig.node_id(f"{name}{index}"), f"{name}{index}", index)
    return folder


async def test_srv17_browse_result_mask_and_node_class_mask(access_rig: AccessRig) -> None:
    """Part 4, 5.9.2.2, 7.29."""
    folder = await folder_with_children(access_rig, "MaskFolder", 2)
    await folder.add_object(access_rig.node_id("MaskObject"), "MaskObject")
    full = (await browse(access_rig.user, children_of(folder.nodeid)))[0]
    assert len(full.References) == 3
    variables = (await browse(access_rig.user, children_of(folder.nodeid, node_class_mask=ua.NodeClass.Variable)))[0]
    assert {r.BrowseName.Name for r in variables.References} == {"MaskFolder0", "MaskFolder1"}
    only_names = ua.BrowseResultMask.BrowseName
    bare = (await browse(access_rig.user, children_of(folder.nodeid, result_mask=only_names)))[0]
    for reference in bare.References:
        assert reference.BrowseName.Name
        assert reference.DisplayName.Text is None or reference.DisplayName.Text == ""
        assert reference.ReferenceTypeId.is_null()
        assert reference.NodeClass == ua.NodeClass.Unspecified
        assert reference.TypeDefinition.is_null()
        assert not reference.NodeId.is_null()
    assert [r.TypeDefinition for r in full.References if r.NodeClass == ua.NodeClass.Variable] == [
        ua.NodeId(ua.ObjectIds.BaseDataVariableType)
    ] * 2


async def test_srv17_browse_view_is_unknown(access_rig: AccessRig) -> None:
    """Part 4, 5.9.2.3."""
    view = ua.ViewDescription(ViewId=ua.NodeId(ua.ObjectIds.Server))
    with pytest.raises(UaStatusCodeError) as error:
        await browse(access_rig.user, description(ua.NodeId(ua.ObjectIds.ObjectsFolder)), view=view)
    assert error.value.code == ua.StatusCodes.BadViewIdUnknown
    null_view = ua.ViewDescription(ViewId=ua.NodeId())
    result = await browse(access_rig.user, description(ua.NodeId(ua.ObjectIds.ObjectsFolder)), view=null_view)
    assert result[0].StatusCode.is_good()


async def test_srv17_browse_direction_invalid(access_rig: AccessRig) -> None:
    """Part 4, 5.9.2.4."""
    objects = ua.NodeId(ua.ObjectIds.ObjectsFolder)
    result = (await browse(access_rig.user, description(objects, direction=ua.BrowseDirection.Invalid)))[0]
    assert result.StatusCode == code(ua.StatusCodes.BadBrowseDirectionInvalid)
    assert result.References == []


async def test_srv56_browse_reference_type_must_be_a_reference_type(access_rig: AccessRig) -> None:
    """Part 4, 5.9.2.4."""
    objects = ua.NodeId(ua.ObjectIds.ObjectsFolder)
    for not_a_reference_type in (ua.NodeId(ua.ObjectIds.Server), ua.NodeId("Nothing", access_rig.ns)):
        result = (await browse(access_rig.user, description(objects, reference_type=not_a_reference_type)))[0]
        assert result.StatusCode == code(ua.StatusCodes.BadReferenceTypeIdInvalid)
        assert result.References == []
    organizes = (await browse(access_rig.user, description(objects, reference_type=ua.NodeId(ua.ObjectIds.Organizes))))[
        0
    ]
    assert organizes.StatusCode.is_good()
    assert len(organizes.References) > 0


async def test_srv17_unknown_node_is_node_id_unknown_in_browse_translate_call(access_rig: AccessRig) -> None:
    """Part 4, 5.9.2.4, 5.9.4.2."""
    unknown = ua.NodeId("Nothing", access_rig.ns)
    result = await browse(access_rig.user, description(unknown), description(ua.NodeId()))
    assert result[0].StatusCode == code(ua.StatusCodes.BadNodeIdUnknown)
    assert result[1].StatusCode == code(ua.StatusCodes.BadNodeIdInvalid)
    path = ua.BrowsePath(StartingNode=unknown, RelativePath=ua.RelativePath([ua.RelativePathElement()]))
    translated = await access_rig.user.uaclient.translate_browsepaths_to_nodeids([path])
    assert translated[0].StatusCode == code(ua.StatusCodes.BadNodeIdUnknown)


async def test_srv17_browse_next_pages_through_all_references(access_rig: AccessRig) -> None:
    """Part 4, 5.9.2, 5.9.3."""
    folder = await folder_with_children(access_rig, "PagedFolder", 25)
    first = (await browse(access_rig.user, children_of(folder.nodeid), maximum=10))[0]
    assert len(first.References) == 10
    assert first.ContinuationPoint
    names = [r.BrowseName.Name for r in first.References]
    token = first.ContinuationPoint
    pages = 1
    while token:
        page = (await browse_next(access_rig.user, token))[0]
        assert page.StatusCode.is_good()
        assert len(page.References) <= 10
        names.extend(r.BrowseName.Name for r in page.References)
        token = page.ContinuationPoint
        pages += 1
    assert pages == 3
    assert sorted(names) == sorted(f"PagedFolder{i}" for i in range(25))
    used = (await browse_next(access_rig.user, first.ContinuationPoint))[0]
    assert used.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)


async def test_srv17_browse_never_returns_more_than_the_server_cap(access_rig: AccessRig) -> None:
    """Part 4, 7.9."""
    folder = await folder_with_children(access_rig, "CappedFolder", 6)
    iserver = access_rig.server.iserver
    iserver.max_browse_references_per_node = 4
    try:
        first = (await browse(access_rig.user, children_of(folder.nodeid), maximum=100))[0]
        assert len(first.References) == 4
        assert first.ContinuationPoint
        last = (await browse_next(access_rig.user, first.ContinuationPoint))[0]
        assert len(last.References) == 2
        assert not last.ContinuationPoint
    finally:
        iserver.max_browse_references_per_node = 10_000


async def test_srv17_browse_exactly_one_page_has_no_continuation_point(access_rig: AccessRig) -> None:
    """Part 4, 7.6."""
    folder = await folder_with_children(access_rig, "ExactFolder", 4)
    result = (await browse(access_rig.user, children_of(folder.nodeid), maximum=4))[0]
    assert len(result.References) == 4
    assert not result.ContinuationPoint


async def test_srv17_browse_continuation_points_are_limited_and_oldest_released(access_rig: AccessRig) -> None:
    """Part 4, 7.9."""
    folder = await folder_with_children(access_rig, "LimitedFolder", 6)
    iserver = access_rig.server.iserver
    iserver.max_browse_continuation_points = 2
    try:
        tokens = []
        for _ in range(3):
            result = (await browse(access_rig.user, children_of(folder.nodeid), maximum=2))[0]
            assert result.ContinuationPoint
            tokens.append(result.ContinuationPoint)
        released = (await browse_next(access_rig.user, tokens[0]))[0]
        assert released.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)
        for token in tokens[1:]:
            assert (await browse_next(access_rig.user, token, release=True)) == []
        many = await browse(access_rig.user, *[children_of(folder.nodeid)] * 3, maximum=2)
        assert [r.StatusCode for r in many] == [code(0), code(0), code(ua.StatusCodes.BadNoContinuationPoints)]
        assert many[2].References == []
    finally:
        iserver.max_browse_continuation_points = 10


async def test_srv17_browse_next_release(access_rig: AccessRig) -> None:
    """Part 4, 5.9.3.2."""
    folder = await folder_with_children(access_rig, "ReleasedFolder", 6)
    first = (await browse(access_rig.user, children_of(folder.nodeid), maximum=2))[0]
    released = await browse_next(access_rig.user, first.ContinuationPoint, b"unknown token", release=True)
    assert released == []
    after = (await browse_next(access_rig.user, first.ContinuationPoint))[0]
    assert after.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)


async def test_srv17_browse_next_other_session_is_invalid(access_rig: AccessRig) -> None:
    """Part 4, 5.9.3.1."""
    folder = await folder_with_children(access_rig, "OwnedFolder", 6)
    first = (await browse(access_rig.admin, children_of(folder.nodeid), maximum=2))[0]
    stolen = (await browse_next(access_rig.user, first.ContinuationPoint))[0]
    assert stolen.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)
    own = (await browse_next(access_rig.admin, first.ContinuationPoint))[0]
    assert own.StatusCode.is_good()
    assert len(own.References) == 2


async def test_srv17_browse_next_after_reference_change_is_invalid(access_rig: AccessRig) -> None:
    """Part 4, 5.9.3.1, 7.6."""
    folder = await folder_with_children(access_rig, "ChangingFolder", 6)
    first = (await browse(access_rig.user, children_of(folder.nodeid), maximum=2))[0]
    await folder.add_variable(access_rig.node_id("ChangingFolderLate"), "ChangingFolderLate", 1)
    next_page = (await browse_next(access_rig.user, first.ContinuationPoint))[0]
    assert next_page.StatusCode == code(ua.StatusCodes.BadContinuationPointInvalid)


async def test_srv17_browse_next_without_continuation_points_is_nothing_to_do(access_rig: AccessRig) -> None:
    """Part 4, 5.9.3.2."""
    with pytest.raises(UaStatusCodeError) as error:
        await browse_next(access_rig.user)
    assert error.value.code == ua.StatusCodes.BadNothingToDo


async def test_srv17_continuation_points_are_freed_with_the_session(access_rig: AccessRig) -> None:
    """Part 4, 5.9.3.1."""
    folder = await folder_with_children(access_rig, "FreedFolder", 6)
    manager = access_rig.server.iserver.session_manager

    def holders() -> int:
        return sum(1 for session in manager.sessions.values() if len(session.continuation_points))

    before = holders()
    guest = Client(access_rig.user.server_url.geturl().replace("someone", "guest"), timeout=10)
    await guest.connect()
    result = (await browse(guest, children_of(folder.nodeid), maximum=2))[0]
    assert result.ContinuationPoint
    assert holders() == before + 1
    await guest.disconnect()
    assert holders() == before


async def test_srv17_translate_empty_path_is_nothing_to_do(access_rig: AccessRig) -> None:
    """Part 4, 5.9.4.4."""
    objects = ua.NodeId(ua.ObjectIds.ObjectsFolder)
    good = ua.BrowsePath(
        StartingNode=ua.NodeId(ua.ObjectIds.RootFolder),
        RelativePath=ua.RelativePath([ua.RelativePathElement(TargetName=ua.QualifiedName("Objects", 0))]),
    )
    empty = ua.BrowsePath(StartingNode=objects, RelativePath=ua.RelativePath([]))
    results = await access_rig.user.uaclient.translate_browsepaths_to_nodeids([empty, good])
    assert results[0].StatusCode == code(ua.StatusCodes.BadNothingToDo)
    assert results[1].StatusCode.is_good()
    assert results[1].Targets[0].TargetId == objects


async def test_srv19_translate_remaining_path_index_is_max(access_rig: AccessRig) -> None:
    """Part 4, 5.9.4.2, 7.18."""
    path = ua.BrowsePath(
        StartingNode=ua.NodeId(ua.ObjectIds.RootFolder),
        RelativePath=ua.RelativePath([ua.RelativePathElement(TargetName=ua.QualifiedName("Objects", 0))]),
    )
    result = (await access_rig.user.uaclient.translate_browsepaths_to_nodeids([path]))[0]
    assert result.Targets[0].RemainingPathIndex == 0xFFFFFFFF


async def test_srv17_translate_no_match(access_rig: AccessRig) -> None:
    """Part 4, 5.9.4.2."""
    missing = ua.BrowsePath(
        StartingNode=ua.NodeId(ua.ObjectIds.RootFolder),
        RelativePath=ua.RelativePath([ua.RelativePathElement(TargetName=ua.QualifiedName("Nothing", 0))]),
    )
    empty_name = ua.BrowsePath(
        StartingNode=ua.NodeId(ua.ObjectIds.RootFolder),
        RelativePath=ua.RelativePath(
            [ua.RelativePathElement(TargetName=ua.QualifiedName("", 0)), ua.RelativePathElement()]
        ),
    )
    results = await access_rig.user.uaclient.translate_browsepaths_to_nodeids([missing, empty_name])
    assert results[0].StatusCode == code(ua.StatusCodes.BadNoMatch)
    assert results[1].StatusCode == code(ua.StatusCodes.BadBrowseNameInvalid)


async def test_srv17_translate_follows_inverse_references_and_live_names(access_rig: AccessRig) -> None:
    """Part 4, 5.9.4.1, 7.30."""
    folder = await folder_with_children(access_rig, "TranslateFolder", 1)
    child = ua.NodeId("TranslateFolder0", access_rig.ns)
    up = ua.BrowsePath(
        StartingNode=child,
        RelativePath=ua.RelativePath(
            [ua.RelativePathElement(IsInverse=True, TargetName=ua.QualifiedName("TranslateFolder", 0))]
        ),
    )
    result = (await access_rig.user.uaclient.translate_browsepaths_to_nodeids([up]))[0]
    assert result.Targets[0].TargetId == folder.nodeid
