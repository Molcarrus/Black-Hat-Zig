const std = @import("std");

// @NUL0x4C | @mrd0x : MalDevAcademy
// Build configuration by CX330Blake - 2025-06-09 00:54:23

pub fn build(b: *std.Build) void {
    // Proper Windows target configuration
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu, // Use GNU ABI instead of MSVC for better compatibility
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "dot_rsrc_section",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Configure for Windows compatibility
    exe.linkLibC();
    exe.subsystem = .Console;

    // Install the executable
    b.installArtifact(exe);

    // Create run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the embedded payload demo");
    run_step.dependOn(&run_cmd.step);

    // Create a test step
    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
