<?php

namespace OCA\OrganizationFolders\Security;

use OCP\IUser;
use OCP\IGroupManager;

use OCA\OrganizationFolders\Db\Resource;
use OCA\OrganizationFolders\Db\ResourceMember;
use OCA\OrganizationFolders\Model\OrganizationFolder;
use OCA\OrganizationFolders\Model\UserPrincipal;
use OCA\OrganizationFolders\Model\PrincipalBackedByGroup;
use OCA\OrganizationFolders\Service\OrganizationFolderService;
use OCA\OrganizationFolders\Service\OrganizationFolderMemberService;
use OCA\OrganizationFolders\Service\ResourceService;
use OCA\OrganizationFolders\Service\ResourceMemberService;
use OCA\OrganizationFolders\Enum\ResourceMemberPermissionLevel;
use OCA\OrganizationFolders\OrganizationProvider\OrganizationProviderManager;
use OCA\OrganizationFolders\Security\OrganizationFolderVoter;

class ResourceVoter extends Voter {
	public function __construct(
		private OrganizationFolderService $organizationFolderService,
		private OrganizationFolderMemberService $organizationFolderMemberService,
		private ResourceService $resourceService,
		private ResourceMemberService $resourceMemberService,
		private IGroupManager $groupManager,
		private OrganizationProviderManager $organizationProviderManager,
		private OrganizationFolderVoter $organizationFolderVoter,
	) {
	}
	protected function supports(string $attribute, mixed $subject): bool {
		return $subject instanceof Resource || $subject === Resource::class;
	}


	protected function voteOnAttribute(string $attribute, mixed $subject, ?IUser $user): bool {
		if (!$user) {
			return false;
		}

		/** @var Resource */
		$resource = $subject;
		return match ($attribute) {
			'READ' => $this->isGranted( $user, $resource),
			'READ_DIRECT' => $this->isResourceManagerDirect( $user, $resource),
			// can read limited information about the resource (true: limited read is allowed, full read may be allowed, false: limited read is not allowed, full read may be allowed (!))
			'READ_LIMITED' => $this->isGrantedLimitedRead($user, $resource),
			'UPDATE' => $this->isGranted($user, $resource),
			'DELETE' => $this->isGranted($user, $resource),
			'UPDATE_MEMBERS' => $this->isGranted($user, $resource),
			'UPDATE_LINK_SHARES' => $this->isGranted($user, $resource),
			'CREATE_SUBRESOURCE' => $this->isGranted($user, $resource),
			'RESTORE_FROM_SNAPSHOT' => $this->isGranted($user, $resource),
			default => throw new \LogicException('This code should not be reached!')
		};
	}

	private function allowedToManageAllResourcesInOrganizationFolder(IUser $user, OrganizationFolder $resourceOrganizationFolder): bool {
		return $this->organizationFolderVoter->vote($user, $resourceOrganizationFolder, ["MANAGE_ALL_RESOURCES"]) === self::ACCESS_GRANTED;
	}

	/**
	 * Return wether user is a manager of the resource DIRECTLY (not through any inheritance from parent resources or the organization folder)
	 * @param IUser $user
	 * @param Resource $resource
	 * @return bool
	 */
	/**
	 * Whether the user is a direct manager of any resource within the
	 * organization folder.
	 *
	 * This is equivalent to READ_DIRECT or READ_LIMITED being granted on any of
	 * the folder's top-level resources (manager of the resource itself or of any
	 * descendant), but is evaluated with a single query over all manager members
	 * of the folder instead of iterating and recursing over the resource tree.
	 *
	 * @param IUser $user
	 * @param int $organizationFolderId
	 * @return bool
	 */
	public function isDirectManagerOfAnyResourceInOrganizationFolder(IUser $user, int $organizationFolderId): bool {
		$managerMembers = $this->resourceMemberService->findAllManagersInOrganizationFolder($organizationFolderId);

		foreach($managerMembers as $managerMember) {
			if($this->userIsManagerMember($user, $managerMember)) {
				return true;
			}
		}

		return false;
	}

	private function isResourceManagerDirect(IUser $user, Resource $resource): bool {
		$resourceMembers = $this->resourceMemberService->findAll(
			resourceId: $resource->getId(),
			filters: [
				"permissionLevel" => ResourceMemberPermissionLevel::MANAGER,
			],
		);

		foreach($resourceMembers as $resourceMember) {
			if($this->userIsManagerMember($user, $resourceMember)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Returns whether the given resource member grants the user direct manager
	 * rights (i.e. it is a valid MANAGER member whose principal contains the user).
	 * @param IUser $user
	 * @param ResourceMember $resourceMember
	 * @return bool
	 */
	private function userIsManagerMember(IUser $user, ResourceMember $resourceMember): bool {
		if($resourceMember->getPermissionLevel() !== ResourceMemberPermissionLevel::MANAGER->value) {
			return false;
		}

		$principal = $resourceMember->getPrincipal();

		if(!$principal->isValid()) {
			return false;
		}

		// TODO: use new containsPrincipal functionality
		if($principal instanceof UserPrincipal) {
			return $principal->getId() === $user->getUID();
		} else if($principal instanceof PrincipalBackedByGroup) {
			return $this->userIsInGroup($user, $principal->getBackingGroupId());
		}

		return false;
	}

	/**
	 * @param IUser $user
	 * @param Resource $resource
	 * @param OrganizationFolder $resourceOrganizationFolder
	 * @return bool
	 */
	private function isResourceManager(IUser $user, Resource $resource, OrganizationFolder $resourceOrganizationFolder): bool {
		if($this->isResourceManagerDirect($user, $resource)) {
			return true;
		}

		// inherit manager permissions from level above
		if($resource->getInheritManagers()) {
			if(!is_null($resource->getParentResourceId())) {
				// not top-level resource -> allowed to manage resource if allowed to manage parent resource
				$parentResource = $this->resourceService->getParentResource($resource);

				if(!is_null($parentResource)) {
					return $this->isResourceManager($user, $parentResource, $resourceOrganizationFolder);
				}
			} else {
				// top-level resource -> allowed to manage resource if manager of organization folder
				return $this->organizationFolderVoter->vote($user, $resourceOrganizationFolder, ["MANAGE_TOP_LEVEL_RESOURCES_WITH_INHERITANCE"]) === self::ACCESS_GRANTED;
			}
		}

		return false;
	}

	protected function isGranted(IUser $user, Resource $resource): bool {
		$resourceOrganizationFolder = $this->organizationFolderService->find($resource->getOrganizationFolderId());

		return $this->allowedToManageAllResourcesInOrganizationFolder($user, $resourceOrganizationFolder)
				|| $this->isResourceManager($user, $resource, $resourceOrganizationFolder);
	}

	/**
	 * Limited read is granted if the user is a direct manager of any descendant
	 * resource (so they need to see this resource in limited form to navigate to it).
	 *
	 * This is equivalent to the previous recursive implementation
	 * (isManagerOfAnySubresource over every descendant), but avoids its redundant
	 * re-traversal of the subtree for every node, and loads the direct manager
	 * members of the whole subtree in a single query instead of one per resource.
	 */
	protected function isGrantedLimitedRead(IUser $user, Resource $resource): bool {
		$subResources = $this->resourceService->getAllSubResources($resource);

		if(count($subResources) === 0) {
			return false;
		}

		$subResourceIds = array_map(static fn(Resource $subResource): int => $subResource->getId(), $subResources);

		$managerMembers = $this->resourceMemberService->findManagersByResourceIds($subResourceIds);

		foreach($managerMembers as $managerMember) {
			if($this->userIsManagerMember($user, $managerMember)) {
				return true;
			}
		}

		return false;
	}

	private function userIsInGroup(IUser $user, string $groupId): bool {
		return $this->groupManager->isInGroup($user->getUID(), $groupId);
	}
}
