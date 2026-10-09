from contextlib import ExitStack
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch as override
import zipfile

from virtualization import patch_controller as controller


def digest(value):
    return hashlib.sha256(value).hexdigest()


def archive_bytes(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as archive:
        archive.comment = b'keep archive comment'
        for name, payload, compression in entries:
            info = zipfile.ZipInfo(name, (2026, 9, 1, 0, 0, 0))
            info.compress_type = compression
            info.external_attr = 0o100644 << 16
            info.comment = b'keep entry comment'
            archive.writestr(info, payload)
    return stream.getvalue()


def class_fixture():
    def utf8(value):
        value = value.encode('ascii')
        return b'\x01' + struct.pack('>H', len(value)) + value
    constants = {
        1: utf8(controller.CLASS_OWNER), 2: b'\x07\x00\x01',
        3: utf8('lEkkVNXwpABkU'), 4: utf8(controller.HELPER_DESCRIPTOR),
        5: b'\x0c\x00\x03\x00\x04', 6: utf8('ROhmZrYJh'),
        7: b'\x0c\x00\x06\x00\x04',
        1127: b'\x0a\x00\x02\x00\x07', 1456: b'\x0a\x00\x02\x00\x05',
    }
    prefix = b'\xca\xfe\xba\xbe\x00\x00\x00\x45' + struct.pack('>H', 1457)
    prefix += b''.join(constants.get(i, utf8('')) for i in range(1, 1457))
    prefix += b'other-model-call:' + controller.OLD_CALL
    method = b'\x00' + controller.OLD_CALL + b'\x00' + controller.OLD_CALL + b'\xb1'
    source = prefix + method + b'unchanged stack maps and other methods'
    expected = prefix + method.replace(controller.OLD_CALL, controller.NEW_CALL) + source[len(prefix) + len(method):]
    values = {
        'CLASS_SHA256': digest(source), 'RESULT_CLASS_SHA256': digest(expected),
        'METHOD_OFFSET': len(prefix), 'METHOD_SIZE': len(method), 'PATCH_OFFSETS': (1, 5),
        'METHOD_SHA256': digest(method),
        'RESULT_METHOD_SHA256': digest(method.replace(controller.OLD_CALL, controller.NEW_CALL)),
    }
    return source, expected, values


def gcm_class_fixture():
    def utf8(value):
        value = value.encode('ascii')
        return b'\x01' + struct.pack('>H', len(value)) + value
    constants = {
        1: utf8(controller.GCM_CLASS_NAME[:-6]), 2: b'\x07\x00\x01',
        3: utf8('com/ubnt/net/VqUfr'), 4: b'\x07\x00\x03',
        5: utf8('ROhmZrYJh'), 6: utf8('Lcom/ubnt/net/VqUfr;'),
        7: b'\x0c\x00\x05\x00\x06',
        8: utf8(controller.GCM_METHOD_NAME), 9: utf8(controller.GCM_DESCRIPTOR),
        10: utf8('Code'), 11: utf8('StackMapTable'), 428: b'\x09\x00\x04\x00\x07',
    }
    prefix = b'\xca\xfe\xba\xbe\x00\x00\x00\x45' + struct.pack('>H', 429)
    prefix += b''.join(constants.get(i, utf8('')) for i in range(1, 429))
    prefix += b'unrelated method and class attributes unchanged'
    prefix += struct.pack('>HHHHHIHHI', 1, 8, 9, 2, 10, 97, 4, 6, 70)
    method = bytes.fromhex(
        '2db201aca600412c12e903b602179a00372bb802933a042ab401cc1904b602ae3a05'
        '2ab401cc190512e904b80382b602be2c12e904b80382b6024b572ab401cc1904b602cab1')
    tail = struct.pack('>HHHI', 0, 1, 11, 9) + controller.GCM_STACK_MAP + b'unchanged annotations'
    source = prefix + method + tail
    changed = method[:14] + b'\x57\0\0' + method[17:]
    expected = prefix + changed + tail
    return source, expected, {
        'GCM_CLASS_SHA256': digest(source), 'GCM_RESULT_CLASS_SHA256': digest(expected),
        'GCM_CODE_OFFSET': len(prefix), 'GCM_CODE_SHA256': digest(method),
        'GCM_RESULT_CODE_SHA256': digest(changed),
    }


class ControllerPatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source, self.output = self.root / 'ace.jar', self.root / 'adapted.jar'
        self.original_class, self.expected_class, self.guards = class_fixture()
        self.original_gcm, self.expected_gcm, gcm_guards = gcm_class_fixture()
        self.guards.update(gcm_guards)
        self.nested = archive_bytes([
            ('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\r\n', zipfile.ZIP_DEFLATED),
            (controller.CLASS_NAME, self.original_class, zipfile.ZIP_DEFLATED),
            (controller.GCM_CLASS_NAME, self.original_gcm, zipfile.ZIP_DEFLATED),
            ('other.class', b'never modify another model or class', zipfile.ZIP_STORED),
        ])
        self.original = archive_bytes([
            ('before.class', b'compressed outer class' * 100, zipfile.ZIP_DEFLATED),
            ('META-INF/BOOT.SF', b'', zipfile.ZIP_STORED),
            (controller.NESTED_NAME, self.nested, zipfile.ZIP_STORED),
            ('BOOT-INF/lib/signed-third-party.jar', b'opaque unchanged library', zipfile.ZIP_STORED),
            ('after.class', b'another compressed class' * 100, zipfile.ZIP_DEFLATED),
        ])
        self.source.write_bytes(self.original)
        self.guards.update(SOURCE_SHA256=digest(self.original), NESTED_SHA256=digest(self.nested))

    def overrides(self):
        stack = ExitStack()
        for name, value in self.guards.items():
            stack.enter_context(override.object(controller, name, value))
        return stack

    def test_only_target_method_references_change(self):
        with self.overrides():
            actual = controller.patch_class(self.original_class)
        self.assertEqual(actual, self.expected_class)
        changed = [i for i, pair in enumerate(zip(actual, self.original_class)) if pair[0] != pair[1]]
        start = self.guards['METHOD_OFFSET']
        self.assertEqual(changed, [start + 2, start + 3, start + 6, start + 7])
        self.assertEqual(len(actual), len(self.original_class))

    def test_method_hash_and_helper_semantics_are_independent_guards(self):
        with self.overrides(), override.object(controller, 'METHOD_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'seedPortTable'):
                controller.patch_class(self.original_class)
        with self.overrides(), override.object(controller, 'HELPER_DESCRIPTOR', '()V'):
            with self.assertRaisesRegex(ValueError, 'helper'):
                controller.patch_class(self.original_class)

    def test_unknown_outer_class_and_nested_hashes_refuse(self):
        with self.assertRaisesRegex(ValueError, 'original ace.jar'):
            controller.patch(self.source, self.output)
        self.assertFalse(self.output.exists())
        with self.overrides(), override.object(controller, 'NESTED_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'original nested'):
                controller.patch(self.source, self.output)
        with self.overrides(), override.object(controller, 'CLASS_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'controller class'):
                controller.patch(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_gcm_patch_keeps_enum_gate_setter_body_and_terminal_frame(self):
        with self.overrides():
            actual = controller.patch_gcm_class(self.original_gcm)
        self.assertEqual(actual, self.expected_gcm)
        start = self.guards['GCM_CODE_OFFSET']
        changed = [i for i, (left, right) in enumerate(zip(actual, self.original_gcm)) if left != right]
        self.assertEqual(changed, [start + 14, start + 16])
        self.assertEqual(actual[start:start + 7], self.original_gcm[start:start + 7])
        self.assertEqual(actual[start + 17:], self.original_gcm[start + 17:])

    def test_gcm_exact_class_code_frame_and_enum_are_independent_guards(self):
        with self.overrides(), override.object(controller, 'GCM_CLASS_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'GCM listener class'):
                controller.patch_gcm_class(self.original_gcm)
        with self.overrides(), override.object(controller, 'GCM_CODE_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'GCM listener method'):
                controller.patch_gcm_class(self.original_gcm)
        wrong_frame = bytearray(self.original_gcm)
        wrong_frame[self.guards['GCM_CODE_OFFSET'] + 70 + 10 + 4] ^= 1
        with self.overrides(), override.object(controller, 'GCM_CLASS_SHA256', digest(wrong_frame)):
            with self.assertRaisesRegex(ValueError, 'stack frame'):
                controller.patch_gcm_class(wrong_frame)
        wrong_enum = self.original_gcm.replace(b'ROhmZrYJh', b'NotTheGCM', 1)
        with self.overrides(), override.object(controller, 'GCM_CLASS_SHA256', digest(wrong_enum)):
            with self.assertRaisesRegex(ValueError, 'enum identity'):
                controller.patch_gcm_class(wrong_enum)
        with self.overrides(), self.assertRaisesRegex(ValueError, 'GCM listener class'):
            controller.patch_gcm_class(self.expected_gcm)

    def test_gcm_branch_consumes_boolean_and_never_reconciles_cbc(self):
        # Execute the actual guard opcodes up to the unchanged synchronization
        # body. This detects a NOP-only change that would leave a boolean behind.
        start = self.guards['GCM_CODE_OFFSET']
        original = self.original_gcm[start:start + 70]
        adapted = self.expected_gcm[start:start + 70]

        def target(code, gcm, mini_flag):
            stack = ['GCM' if gcm else 'CBC']
            self.assertEqual(code[0:2], b'\x2d\xb2')
            stack.append('GCM')
            self.assertEqual(code[4], 0xa6)
            right, left = stack.pop(), stack.pop()
            if right != left:
                return 4 + int.from_bytes(code[5:7], 'big'), stack
            stack.append(mini_flag)  # Existing getBoolean() at offset11.
            if code[14] == 0x9a:
                taken = stack.pop()
                return (14 + int.from_bytes(code[15:17], 'big') if taken else 17), stack
            self.assertEqual(code[14:17], b'\x57\0\0')
            stack.pop()
            return 17, stack

        for mini_flag in (False, True):
            self.assertEqual(target(adapted, False, mini_flag), (69, []))
            self.assertEqual(target(adapted, True, mini_flag), (17, []))
        self.assertEqual(target(original, True, True), (69, []))
        self.assertEqual(target(original, True, False), (17, []))

    def test_unknown_second_class_refuses_before_creating_output(self):
        with self.overrides(), override.object(controller, 'GCM_CLASS_SHA256', '0' * 64):
            with self.assertRaisesRegex(ValueError, 'GCM listener class'):
                controller.patch(self.source, self.output)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.output.with_name(self.output.name + '.internal.jar').exists())

    def test_build_and_guest_install_are_byte_identical(self):
        nested_path = self.root / 'payload.jar'
        installed = self.root / 'installed.jar'
        with self.overrides():
            report = controller.patch(self.source, self.output, nested_path)
            controller.install(self.source, installed, nested_path,
                               report['nested_result_sha256'], report['result_sha256'])
        self.assertEqual(report['changed_classes'], [controller.CLASS_NAME, controller.GCM_CLASS_NAME])
        self.assertTrue(report['unlisted_classes_unchanged'])
        self.assertNotIn('other_classes_unchanged', report)
        self.assertEqual(self.output.read_bytes(), installed.read_bytes())
        self.assertEqual(self.source.read_bytes(), self.original)
        with zipfile.ZipFile(self.source) as before, zipfile.ZipFile(installed) as after:
            self.assertEqual(before.namelist(), after.namelist())
            self.assertEqual(before.comment, after.comment)
            self.assertIsNone(after.testzip())
            for info in before.infolist():
                newer = after.getinfo(info.filename)
                self.assertEqual(info.compress_type, newer.compress_type)
                self.assertEqual(info.comment, newer.comment)
                self.assertEqual(info.external_attr, newer.external_attr)
                if info.filename != controller.NESTED_NAME:
                    self.assertEqual(before.read(info), after.read(info.filename))
                    # The stream splicer preserves even compressed payloads,
                    # so runtime output cannot depend on guest zlib versions.
                    def raw_payload(path, member):
                        with path.open('rb') as stream:
                            stream.seek(member.header_offset)
                            header = stream.read(30)
                            name_size, extra_size = struct.unpack_from('<2H', header, 26)
                            stream.seek(name_size + extra_size, 1)
                            return stream.read(member.compress_size)
                    self.assertEqual(raw_payload(self.source, info), raw_payload(installed, newer))
            with zipfile.ZipFile(io.BytesIO(after.read(controller.NESTED_NAME))) as nested:
                self.assertEqual(nested.read(controller.CLASS_NAME), self.expected_class)
                self.assertEqual(nested.read(controller.GCM_CLASS_NAME), self.expected_gcm)
                self.assertEqual(nested.read('other.class'), b'never modify another model or class')
                with zipfile.ZipFile(io.BytesIO(self.nested)) as original_nested:
                    self.assertEqual(nested.namelist(), original_nested.namelist())
                    self.assertEqual(nested.comment, original_nested.comment)
                    for entry in original_nested.infolist():
                        newer = nested.getinfo(entry.filename)
                        self.assertEqual((entry.compress_type, entry.date_time, entry.comment, entry.external_attr),
                                         (newer.compress_type, newer.date_time, newer.comment, newer.external_attr))
                        if entry.filename not in (controller.CLASS_NAME, controller.GCM_CLASS_NAME):
                            self.assertEqual(original_nested.read(entry), nested.read(newer))

    def test_guest_install_rejects_unpatched_second_class_even_with_matching_archive_hash(self):
        nested_path = self.root / 'wrong-payload.jar'
        nested_path.write_bytes(archive_bytes([
            (controller.CLASS_NAME, self.expected_class, zipfile.ZIP_DEFLATED),
            (controller.GCM_CLASS_NAME, self.original_gcm, zipfile.ZIP_DEFLATED),
        ]))
        with self.overrides(), self.assertRaisesRegex(ValueError, 'adapted GCM listener class'):
            controller.install(self.source, self.output, nested_path, digest(nested_path.read_bytes()), None)
        self.assertFalse(self.output.exists())

    def test_real_signatures_and_manifest_digests_are_refused(self):
        for name, data in [('META-INF/SIGNER.SF', b'Signature-Version: 1.0'),
                           ('META-INF/BOOT.SF', b'not empty'), ('META-INF/X.RSA', b''),
                           ('META-INF/MANIFEST.MF', b'SHA-256-Digest: abcd')]:
            blob = archive_bytes([(name, data, zipfile.ZIP_STORED)])
            with self.subTest(name=name), zipfile.ZipFile(io.BytesIO(blob)) as archive:
                with self.assertRaisesRegex(ValueError, 'Signed|digests'):
                    controller.guard_archive(archive)

    def test_nonstored_nested_library_is_refused(self):
        source = self.root / 'compressed.jar'
        source.write_bytes(archive_bytes([(controller.NESTED_NAME, self.nested, zipfile.ZIP_DEFLATED)]))
        replacement = self.root / 'payload.jar'
        replacement.write_bytes(self.nested)
        with self.assertRaisesRegex(ValueError, 'STORED'):
            controller.replace_stored_member(source, self.output, controller.NESTED_NAME, replacement)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.output.write_bytes(b'keep')
        with self.overrides(), self.assertRaisesRegex(ValueError, 'already exists'):
            controller.patch(self.source, self.output)
        self.assertEqual(self.output.read_bytes(), b'keep')


if __name__ == '__main__':
    unittest.main()
